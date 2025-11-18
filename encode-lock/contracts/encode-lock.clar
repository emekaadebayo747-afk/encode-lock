;; EncodeLock - Blockchain Security Monitoring Platform
;; A decentralized security monitoring system for dApps on Stacks

;; Constants
(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u100))
(define-constant err-not-found (err u101))
(define-constant err-already-exists (err u102))
(define-constant err-unauthorized (err u103))
(define-constant err-threshold-not-met (err u104))

;; Data Variables
(define-data-var emergency-mode bool false)
(define-data-var alert-threshold uint u3)
(define-data-var total-monitored-contracts uint u0)

;; Data Maps
(define-map monitored-contracts 
  principal 
  {
    risk-level: uint,
    is-active: bool,
    last-alert: uint,
    alert-count: uint
  }
)

(define-map validator-nodes
  principal
  {
    reputation-score: uint,
    alerts-validated: uint,
    is-active: bool
  }
)

(define-map threat-alerts
  uint
  {
    contract: principal,
    threat-type: (string-ascii 50),
    severity: uint,
    timestamp: uint,
    validator-votes: uint,
    is-confirmed: bool
  }
)

(define-map security-incidents
  {contract: principal, incident-id: uint}
  {
    description: (string-ascii 256),
    resolved: bool,
    resolution-timestamp: (optional uint)
  }
)

(define-data-var alert-nonce uint u0)

;; Read-only functions

(define-read-only (get-emergency-mode)
  (var-get emergency-mode)
)

(define-read-only (get-contract-status (contract principal))
  (map-get? monitored-contracts contract)
)

(define-read-only (get-validator-info (validator principal))
  (map-get? validator-nodes validator)
)

(define-read-only (get-threat-alert (alert-id uint))
  (map-get? threat-alerts alert-id)
)

(define-read-only (get-total-monitored)
  (var-get total-monitored-contracts)
)

(define-read-only (is-contract-at-risk (contract principal))
  (match (map-get? monitored-contracts contract)
    contract-data (>= (get risk-level contract-data) u7)
    false
  )
)

;; Public functions

(define-public (register-monitored-contract (contract principal))
  (begin
    (asserts! (is-eq tx-sender contract-owner) err-owner-only)
    (asserts! (is-none (map-get? monitored-contracts contract)) err-already-exists)
    (map-set monitored-contracts contract {
      risk-level: u0,
      is-active: true,
      last-alert: u0,
      alert-count: u0
    })
    (var-set total-monitored-contracts (+ (var-get total-monitored-contracts) u1))
    (ok true)
  )
)

(define-public (register-validator (validator principal))
  (begin
    (asserts! (is-eq tx-sender contract-owner) err-owner-only)
    (asserts! (is-none (map-get? validator-nodes validator)) err-already-exists)
    (map-set validator-nodes validator {
      reputation-score: u100,
      alerts-validated: u0,
      is-active: true
    })
    (ok true)
  )
)

(define-public (submit-threat-alert 
    (contract principal) 
    (threat-type (string-ascii 50)) 
    (severity uint))
  (let
    (
      (alert-id (var-get alert-nonce))
      (validator-info (unwrap! (map-get? validator-nodes tx-sender) err-unauthorized))
    )
    (asserts! (get is-active validator-info) err-unauthorized)
    (asserts! (is-some (map-get? monitored-contracts contract)) err-not-found)
    
    (map-set threat-alerts alert-id {
      contract: contract,
      threat-type: threat-type,
      severity: severity,
      timestamp: block-height,
      validator-votes: u1,
      is-confirmed: false
    })
    
    (var-set alert-nonce (+ alert-id u1))
    (ok alert-id)
  )
)

(define-public (vote-on-alert (alert-id uint))
  (let
    (
      (alert-data (unwrap! (map-get? threat-alerts alert-id) err-not-found))
      (validator-info (unwrap! (map-get? validator-nodes tx-sender) err-unauthorized))
      (new-votes (+ (get validator-votes alert-data) u1))
    )
    (asserts! (get is-active validator-info) err-unauthorized)
    (asserts! (not (get is-confirmed alert-data)) err-already-exists)
    
    (map-set threat-alerts alert-id
      (merge alert-data {validator-votes: new-votes})
    )
    
    ;; Update validator reputation
    (map-set validator-nodes tx-sender
      (merge validator-info {
        alerts-validated: (+ (get alerts-validated validator-info) u1)
      })
    )
    
    ;; Check if threshold is met
    (if (>= new-votes (var-get alert-threshold))
      (begin
        (try! (confirm-threat alert-id))
        (ok true)
      )
      (ok true)
    )
  )
)

(define-public (confirm-threat (alert-id uint))
  (let
    (
      (alert-data (unwrap! (map-get? threat-alerts alert-id) err-not-found))
      (contract (get contract alert-data))
      (contract-data (unwrap! (map-get? monitored-contracts contract) err-not-found))
    )
    (asserts! (>= (get validator-votes alert-data) (var-get alert-threshold)) err-threshold-not-met)
    
    ;; Mark alert as confirmed
    (map-set threat-alerts alert-id
      (merge alert-data {is-confirmed: true})
    )
    
    ;; Update contract risk level
    (map-set monitored-contracts contract
      (merge contract-data {
        risk-level: (+ (get risk-level contract-data) (get severity alert-data)),
        last-alert: block-height,
        alert-count: (+ (get alert-count contract-data) u1)
      })
    )
    
    ;; Activate circuit breaker if risk is critical
    (if (>= (get severity alert-data) u8)
      (var-set emergency-mode true)
      true
    )
    
    (ok true)
  )
)

(define-public (toggle-emergency-mode)
  (begin
    (asserts! (is-eq tx-sender contract-owner) err-owner-only)
    (var-set emergency-mode (not (var-get emergency-mode)))
    (ok (var-get emergency-mode))
  )
)

(define-public (update-contract-risk (contract principal) (new-risk-level uint))
  (let
    (
      (contract-data (unwrap! (map-get? monitored-contracts contract) err-not-found))
    )
    (asserts! (is-eq tx-sender contract-owner) err-owner-only)
    (map-set monitored-contracts contract
      (merge contract-data {risk-level: new-risk-level})
    )
    (ok true)
  )
)

(define-public (deactivate-contract (contract principal))
  (let
    (
      (contract-data (unwrap! (map-get? monitored-contracts contract) err-not-found))
    )
    (asserts! (is-eq tx-sender contract-owner) err-owner-only)
    (map-set monitored-contracts contract
      (merge contract-data {is-active: false})
    )
    (ok true)
  )
)

(define-public (record-incident 
    (contract principal) 
    (incident-id uint) 
    (description (string-ascii 256)))
  (begin
    (asserts! (is-some (map-get? monitored-contracts contract)) err-not-found)
    (map-set security-incidents 
      {contract: contract, incident-id: incident-id}
      {
        description: description,
        resolved: false,
        resolution-timestamp: none
      }
    )
    (ok true)
  )
)

(define-public (resolve-incident (contract principal) (incident-id uint))
  (let
    (
      (incident-data (unwrap! (map-get? security-incidents {contract: contract, incident-id: incident-id}) err-not-found))
    )
    (asserts! (is-eq tx-sender contract-owner) err-owner-only)
    (map-set security-incidents
      {contract: contract, incident-id: incident-id}
      (merge incident-data {
        resolved: true,
        resolution-timestamp: (some block-height)
      })
    )
    (ok true)
  )
)

;; Initialize contract
(begin
  (map-set validator-nodes contract-owner {
    reputation-score: u100,
    alerts-validated: u0,
    is-active: true
  })
)