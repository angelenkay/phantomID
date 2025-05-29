;; PhantomID Protocol
;; A next-generation privacy-preserving identity system that enables anonymous verification,
;; decentralized reputation scoring, and secure group interactions through advanced
;; cryptographic primitives while maintaining absolute user privacy.

;; ERROR DEFINITIONS & SYSTEM CONSTANTS

(define-constant admin tx-sender)
(define-constant ERR-ACCESS-DENIED (err u100))
(define-constant ERR-PHANTOM-EXISTS (err u101))
(define-constant ERR-PHANTOM-NOT-FOUND (err u102))
(define-constant ERR-INVALID-COMMITMENT (err u103))
(define-constant ERR-VERIFICATION-FAILED (err u104))
(define-constant ERR-LOW-REPUTATION (err u105))
(define-constant ERR-INVALID-PROOF (err u106))
(define-constant ERR-EXPIRED (err u107))
(define-constant ERR-ALREADY-VERIFIED (err u108))
(define-constant ERR-INVALID-PARAMS (err u109))
(define-constant ERR-SYSTEM-LOCKED (err u110))
(define-constant ERR-ACCESS-FORBIDDEN (err u111))

;; Protocol Configuration
(define-constant reputation-floor u10)
(define-constant reputation-cap u1000)
(define-constant challenge-timeout u144) ;; ~24 hours
(define-constant commitment-lifespan u1008) ;; ~1 week
(define-constant starter-reputation u100)
(define-constant max-interaction-types u10)
(define-constant max-challenge-types u5)
(define-constant max-proof-categories u10)

;; ===========================================
;; CORE DATA MODELS
;; ===========================================

;; Anonymous phantom identity storage
(define-map phantom-vault
  { phantom-hash: (buff 32) }
  {
    secret-seal: (buff 32),
    reputation-score: uint,
    trust-tier: uint,
    birth-block: uint,
    last-seen: uint,
    is-active: bool,
    metadata-cipher: (optional (buff 32))
  }
)

;; Private ownership linkage (hidden from public view)
(define-map owner-ledger
  { wallet: principal }
  { 
    phantom-id: (buff 32), 
    claim-block: uint 
  }
)

;; Challenge management system
(define-map challenge-arena
  { challenge-hash: (buff 32) }
  {
    target-phantom: (buff 32),
    challenger: principal,
    challenge-type: uint,
    proof-seal: (buff 32),
    created-at: uint,
    is-resolved: bool,
    outcome: (optional bool)
  }
)

;; Reputation transaction history
(define-map rep-ledger
  { tx-hash: (buff 32) }
  {
    giver-phantom: (buff 32),
    receiver-phantom: (buff 32),
    interaction-type: uint,
    rep-delta: int,
    timestamp: uint,
    proof-ref: (buff 32)
  }
)

;; Zero-knowledge proof repository
(define-map proof-vault
  { proof-hash: (buff 32) }
  {
    owner-phantom: (buff 32),
    proof-type: uint,
    zk-payload: (buff 512),
    is-verified: bool,
    submitted-at: uint
  }
)

;; Anonymous collective management
(define-map collective-registry
  { collective-hash: (buff 32) }
  {
    display-name: (string-ascii 64),
    min-reputation: uint,
    member-count: uint,
    founded-at: uint,
    is-operational: bool
  }
)

;; Anonymous membership tracking
(define-map membership-vault
  { membership-hash: (buff 32) }
  {
    collective-id: (buff 32),
    privacy-seal: (buff 32),
    joined-at: uint,
    is-member: bool
  }
)

;; SYSTEM STATE TRACKERS

(define-data-var total-phantoms uint u0)
(define-data-var verified-count uint u0)
(define-data-var reputation-treasury uint u10000)
(define-data-var min-verify-threshold uint u50)
(define-data-var system-paused bool false)

;; UTILITY FUNCTIONS

;; Generate secure hash for dual inputs
(define-private (forge-hash 
  (input-a (buff 32)) 
  (input-b (buff 32)) 
  (salt uint))
  (keccak256 
    (concat 
      (concat input-a input-b) 
      (unwrap-panic (to-consensus-buff? salt))
    )
  )
)

;; Generate hash for large proof data
(define-private (forge-proof-hash 
  (phantom-id (buff 32)) 
  (proof-data (buff 512)) 
  (salt uint))
  (keccak256 
    (concat 
      (concat phantom-id (keccak256 proof-data)) 
      (unwrap-panic (to-consensus-buff? salt))
    )
  )
)

;; Validate commitment structure
(define-private (valid-seal (seal (buff 32)))
  (> (len seal) u0)
)

;; Check phantom existence
(define-private (phantom-exists (phantom-id (buff 32)))
  (is-some (map-get? phantom-vault { phantom-hash: phantom-id }))
)

;; Get current block height
(define-private (current-height)
  block-height
)

;; Validate reputation change bounds
(define-private (valid-rep-delta (delta int))
  (and (>= delta -100) (<= delta 100))
)

;; Calculate new reputation with bounds
(define-private (calc-new-reputation (current uint) (delta int))
  (let ((new-rep 
         (if (< delta 0)
           (if (>= current (to-uint (- 0 delta)))
             (- current (to-uint (- 0 delta)))
             u0)
           (+ current (to-uint delta)))))
    (if (> new-rep reputation-cap) 
        reputation-cap 
        new-rep))
)

;; Validate proof structure
(define-private (valid-proof (proof (buff 512)))
  (and 
    (> (len proof) u0)
    (<= (len proof) u512)
  )
)

;; Validate hash formats
(define-private (valid-hash-32 (hash (buff 32)))
  (is-eq (len hash) u32)
)

;; Validate optional metadata
(define-private (valid-metadata (meta (optional (buff 32))))
  (match meta
    data (is-eq (len data) u32)
    true
  )
)

;; PUBLIC READ FUNCTIONS

;; Get phantom details
(define-read-only (get-phantom (phantom-id (buff 32)))
  (map-get? phantom-vault { phantom-hash: phantom-id })
)

;; Query reputation score
(define-read-only (get-reputation (phantom-id (buff 32)))
  (match (map-get? phantom-vault { phantom-hash: phantom-id })
    phantom (ok (get reputation-score phantom))
    ERR-PHANTOM-NOT-FOUND
  )
)

;; Check verification status
(define-read-only (is-verified (phantom-id (buff 32)))
  (match (map-get? phantom-vault { phantom-hash: phantom-id })
    phantom (ok (>= (get trust-tier phantom) u1))
    ERR-PHANTOM-NOT-FOUND
  )
)

;; Get challenge details
(define-read-only (get-challenge (challenge-id (buff 32)))
  (map-get? challenge-arena { challenge-hash: challenge-id })
)

;; Get collective info
(define-read-only (get-collective (collective-id (buff 32)))
  (map-get? collective-registry { collective-hash: collective-id })
)

;; System statistics
(define-read-only (get-stats)
  {
    total-phantoms: (var-get total-phantoms),
    verified-count: (var-get verified-count),
    reputation-treasury: (var-get reputation-treasury),
    min-verify-threshold: (var-get min-verify-threshold),
    system-paused: (var-get system-paused)
  }
)

;; Validate proof format
(define-read-only (check-proof-format (proof (buff 512)))
  (valid-proof proof)
)

;; PHANTOM LIFECYCLE

;; Create new phantom identity
(define-public (create-phantom 
  (secret-seal (buff 32)) 
  (metadata (optional (buff 32))))
  (let (
    (phantom-id 
      (keccak256 
        (concat secret-seal 
                (unwrap-panic (to-consensus-buff? block-height)))))
    (now (current-height))
  )
    (asserts! (not (var-get system-paused)) ERR-ACCESS-DENIED)
    (asserts! (valid-seal secret-seal) ERR-INVALID-COMMITMENT)
    (asserts! (not (phantom-exists phantom-id)) ERR-PHANTOM-EXISTS)
    (asserts! (is-none (map-get? owner-ledger { wallet: tx-sender })) ERR-PHANTOM-EXISTS)
    (asserts! (valid-metadata metadata) ERR-INVALID-PARAMS)
    
    ;; Create phantom record
    (map-set phantom-vault
      { phantom-hash: phantom-id }
      {
        secret-seal: secret-seal,
        reputation-score: starter-reputation,
        trust-tier: u0,
        birth-block: now,
        last-seen: now,
        is-active: true,
        metadata-cipher: metadata
      }
    )
    
    ;; Link to owner
    (map-set owner-ledger
      { wallet: tx-sender }
      { 
        phantom-id: phantom-id,
        claim-block: now
      }
    )
    
    ;; Update global stats
    (var-set total-phantoms (+ (var-get total-phantoms) u1))
    
    (ok phantom-id)
  )
)

;; Update phantom activity
(define-public (ping-phantom)
  (let (
    (owner-data (unwrap! (map-get? owner-ledger { wallet: tx-sender }) ERR-PHANTOM-NOT-FOUND))
    (phantom-id (get phantom-id owner-data))
    (phantom-data (unwrap! (map-get? phantom-vault { phantom-hash: phantom-id }) ERR-PHANTOM-NOT-FOUND))
  )
    (asserts! (not (var-get system-paused)) ERR-ACCESS-DENIED)
    (asserts! (get is-active phantom-data) ERR-PHANTOM-NOT-FOUND)
    
    ;; Update last seen timestamp
    (map-set phantom-vault
      { phantom-hash: phantom-id }
      (merge phantom-data { last-seen: (current-height) })
    )
    
    (ok true)
  )
)

;; Deactivate phantom
(define-public (deactivate-phantom)
  (let (
    (owner-data (unwrap! (map-get? owner-ledger { wallet: tx-sender }) ERR-PHANTOM-NOT-FOUND))
    (phantom-id (get phantom-id owner-data))
    (phantom-data (unwrap! (map-get? phantom-vault { phantom-hash: phantom-id }) ERR-PHANTOM-NOT-FOUND))
  )
    (asserts! (not (var-get system-paused)) ERR-ACCESS-DENIED)
    (asserts! (get is-active phantom-data) ERR-PHANTOM-NOT-FOUND)
    
    ;; Set to inactive
    (map-set phantom-vault
      { phantom-hash: phantom-id }
      (merge phantom-data { is-active: false })
    )
    
    (ok true)
  )
)

;; VERIFICATION SYSTEM

;; Start verification challenge
(define-public (start-challenge 
  (target-phantom (buff 32)) 
  (challenge-type uint) 
  (proof-seal (buff 32)))
  (let (
    (challenge-id 
      (forge-hash target-phantom proof-seal (current-height)))
    (now (current-height))
  )
    (asserts! (not (var-get system-paused)) ERR-ACCESS-DENIED)
    (asserts! (valid-hash-32 target-phantom) ERR-INVALID-PARAMS)
    (asserts! (phantom-exists target-phantom) ERR-PHANTOM-NOT-FOUND)
    (asserts! (valid-seal proof-seal) ERR-INVALID-COMMITMENT)
    (asserts! (<= challenge-type max-challenge-types) ERR-INVALID-PARAMS)
    
    ;; Create challenge
    (map-set challenge-arena
      { challenge-hash: challenge-id }
      {
        target-phantom: target-phantom,
        challenger: tx-sender,
        challenge-type: challenge-type,
        proof-seal: proof-seal,
        created-at: now,
        is-resolved: false,
        outcome: none
      }
    )
    
    (ok challenge-id)
  )
)

;; Respond to challenge
(define-public (respond-challenge 
  (challenge-id (buff 32)) 
  (response-proof (buff 512)))
  (let (
    (challenge-data (unwrap! (map-get? challenge-arena { challenge-hash: challenge-id }) ERR-PHANTOM-NOT-FOUND))
    (target-phantom (get target-phantom challenge-data))
    (owner-data (unwrap! (map-get? owner-ledger { wallet: tx-sender }) ERR-PHANTOM-NOT-FOUND))
    (now (current-height))
  )
    (asserts! (not (var-get system-paused)) ERR-ACCESS-DENIED)
    (asserts! (is-eq target-phantom (get phantom-id owner-data)) ERR-ACCESS-DENIED)
    (asserts! (not (get is-resolved challenge-data)) ERR-ALREADY-VERIFIED)
    (asserts! (< (- now (get created-at challenge-data)) challenge-timeout) ERR-EXPIRED)
    (asserts! (valid-proof response-proof) ERR-INVALID-PROOF)
    
    ;; Mark challenge resolved
    (map-set challenge-arena
      { challenge-hash: challenge-id }
      (merge challenge-data { 
        is-resolved: true,
        outcome: (some true)
      })
    )
    
    ;; Increase trust tier
    (try! (boost-trust target-phantom))
    
    ;; Update stats
    (var-set verified-count (+ (var-get verified-count) u1))
    
    (ok true)
  )
)

;; Boost trust tier (admin function)
(define-public (boost-trust (phantom-id (buff 32)))
  (let (
    (phantom-data (unwrap! (map-get? phantom-vault { phantom-hash: phantom-id }) ERR-PHANTOM-NOT-FOUND))
    (new-tier (+ (get trust-tier phantom-data) u1))
  )
    (asserts! (is-eq tx-sender admin) ERR-ACCESS-DENIED)
    
    (map-set phantom-vault
      { phantom-hash: phantom-id }
      (merge phantom-data { trust-tier: new-tier })
    )
    
    (ok new-tier)
  )
)

;; REPUTATION SYSTEM

;; Give reputation
(define-public (give-reputation
  (target-phantom (buff 32))
  (interaction-type uint)
  (rep-delta int)
  (proof-ref (buff 32)))
  (let (
    (sender-data (unwrap! (map-get? owner-ledger { wallet: tx-sender }) ERR-PHANTOM-NOT-FOUND))
    (sender-phantom (get phantom-id sender-data))
    (sender-info (unwrap! (map-get? phantom-vault { phantom-hash: sender-phantom }) ERR-PHANTOM-NOT-FOUND))
    (target-info (unwrap! (map-get? phantom-vault { phantom-hash: target-phantom }) ERR-PHANTOM-NOT-FOUND))
    (tx-id (forge-hash sender-phantom target-phantom (current-height)))
    (now (current-height))
  )
    (asserts! (not (var-get system-paused)) ERR-ACCESS-DENIED)
    (asserts! (get is-active sender-info) ERR-PHANTOM-NOT-FOUND)
    (asserts! (get is-active target-info) ERR-PHANTOM-NOT-FOUND)
    (asserts! (>= (get reputation-score sender-info) reputation-floor) ERR-LOW-REPUTATION)
    (asserts! (valid-rep-delta rep-delta) ERR-INVALID-PARAMS)
    (asserts! (<= interaction-type max-interaction-types) ERR-INVALID-PARAMS)
    
    ;; Record transaction
    (map-set rep-ledger
      { tx-hash: tx-id }
      {
        giver-phantom: sender-phantom,
        receiver-phantom: target-phantom,
        interaction-type: interaction-type,
        rep-delta: rep-delta,
        timestamp: now,
        proof-ref: proof-ref
      }
    )
    
    ;; Apply reputation change
    (let ((new-rep 
           (calc-new-reputation 
             (get reputation-score target-info) 
             rep-delta)))
      (map-set phantom-vault
        { phantom-hash: target-phantom }
        (merge target-info { 
          reputation-score: new-rep,
          last-seen: now
        })
      )
    )
    
    (ok tx-id)
  )
)

;; COLLECTIVE MANAGEMENT

;; Create collective
(define-public (create-collective 
  (name (string-ascii 64)) 
  (min-rep uint))
  (let (
    (collective-id (keccak256 (unwrap-panic (to-consensus-buff? name))))
    (now (current-height))
  )
    (asserts! (not (var-get system-paused)) ERR-ACCESS-DENIED)
    (asserts! (> (len name) u0) ERR-INVALID-PARAMS)
    (asserts! (<= min-rep reputation-cap) ERR-INVALID-PARAMS)
    (asserts! (is-none (map-get? collective-registry { collective-hash: collective-id })) ERR-PHANTOM-EXISTS)
    
    (map-set collective-registry
      { collective-hash: collective-id }
      {
        display-name: name,
        min-reputation: min-rep,
        member-count: u0,
        founded-at: now,
        is-operational: true
      }
    )
    
    (ok collective-id)
  )
)

;; Join collective
(define-public (join-collective 
  (collective-id (buff 32)) 
  (privacy-seal (buff 32)))
  (let (
    (owner-data (unwrap! (map-get? owner-ledger { wallet: tx-sender }) ERR-PHANTOM-NOT-FOUND))
    (phantom-id (get phantom-id owner-data))
    (phantom-info (unwrap! (map-get? phantom-vault { phantom-hash: phantom-id }) ERR-PHANTOM-NOT-FOUND))
    (collective-info (unwrap! (map-get? collective-registry { collective-hash: collective-id }) ERR-PHANTOM-NOT-FOUND))
    (membership-id (forge-hash collective-id privacy-seal (current-height)))
    (now (current-height))
  )
    (asserts! (not (var-get system-paused)) ERR-ACCESS-DENIED)
    (asserts! (get is-operational collective-info) ERR-ACCESS-FORBIDDEN)
    (asserts! (get is-active phantom-info) ERR-PHANTOM-NOT-FOUND)
    (asserts! (>= (get reputation-score phantom-info) (get min-reputation collective-info)) ERR-LOW-REPUTATION)
    (asserts! (valid-seal privacy-seal) ERR-INVALID-COMMITMENT)
    
    ;; Create membership
    (map-set membership-vault
      { membership-hash: membership-id }
      {
        collective-id: collective-id,
        privacy-seal: privacy-seal,
        joined-at: now,
        is-member: true
      }
    )
    
    ;; Update member count
    (map-set collective-registry
      { collective-hash: collective-id }
      (merge collective-info { member-count: (+ (get member-count collective-info) u1) })
    )
    
    (ok membership-id)
  )
)

;; PROOF SYSTEM

;; Submit ZK proof
(define-public (submit-proof 
  (proof-type uint) 
  (zk-payload (buff 512)))
  (let (
    (owner-data (unwrap! (map-get? owner-ledger { wallet: tx-sender }) ERR-PHANTOM-NOT-FOUND))
    (phantom-id (get phantom-id owner-data))
    (proof-id (forge-proof-hash phantom-id zk-payload (current-height)))
    (now (current-height))
  )
    (asserts! (not (var-get system-paused)) ERR-ACCESS-DENIED)
    (asserts! (valid-proof zk-payload) ERR-INVALID-PROOF)
    (asserts! (<= proof-type max-proof-categories) ERR-INVALID-PARAMS)
    
    (map-set proof-vault
      { proof-hash: proof-id }
      {
        owner-phantom: phantom-id,
        proof-type: proof-type,
        zk-payload: zk-payload,
        is-verified: false,
        submitted-at: now
      }
    )
    
    (ok proof-id)
  )
)

;; NEW FUNCTION: Batch reputation transfer
(define-public (batch-reputation-transfer
  (recipients (list 10 (buff 32)))
  (amounts (list 10 int))
  (interaction-type uint))
  (let (
    (sender-data (unwrap! (map-get? owner-ledger { wallet: tx-sender }) ERR-PHANTOM-NOT-FOUND))
    (sender-phantom (get phantom-id sender-data))
    (sender-info (unwrap! (map-get? phantom-vault { phantom-hash: sender-phantom }) ERR-PHANTOM-NOT-FOUND))
  )
    (asserts! (not (var-get system-paused)) ERR-ACCESS-DENIED)
    (asserts! (get is-active sender-info) ERR-PHANTOM-NOT-FOUND)
    (asserts! (>= (get reputation-score sender-info) reputation-floor) ERR-LOW-REPUTATION)
    (asserts! (is-eq (len recipients) (len amounts)) ERR-INVALID-PARAMS)
    (asserts! (<= interaction-type max-interaction-types) ERR-INVALID-PARAMS)
    
    ;; Process each transfer
    (ok (map process-single-transfer recipients amounts))
  )
)

;; Helper for batch processing
(define-private (process-single-transfer (recipient (buff 32)) (amount int))
  (let (
    (target-info (unwrap-panic (map-get? phantom-vault { phantom-hash: recipient })))
    (tx-id (forge-hash recipient (unwrap-panic (to-consensus-buff? amount)) (current-height)))
    (now (current-height))
  )
    (begin
      ;; Record transaction
      (map-set rep-ledger
        { tx-hash: tx-id }
        {
          giver-phantom: (get phantom-id (unwrap-panic (map-get? owner-ledger { wallet: tx-sender }))),
          receiver-phantom: recipient,
          interaction-type: u1,
          rep-delta: amount,
          timestamp: now,
          proof-ref: tx-id
        }
      )
      
      ;; Update reputation
      (map-set phantom-vault
        { phantom-hash: recipient }
        (merge target-info { 
          reputation-score: (calc-new-reputation (get reputation-score target-info) amount),
          last-seen: now
        })
      )
      
      tx-id
    )
  )
)

;; ADMIN FUNCTIONS

;; Toggle system pause
(define-public (toggle-pause (paused bool))
  (begin
    (asserts! (is-eq tx-sender admin) ERR-ACCESS-DENIED)
    (var-set system-paused paused)
    (ok paused)
  )
)

;; Adjust minimum verification threshold
(define-public (set-verify-threshold (threshold uint))
  (begin
    (asserts! (is-eq tx-sender admin) ERR-ACCESS-DENIED)
    (asserts! (<= threshold reputation-cap) ERR-INVALID-PARAMS)
    (var-set min-verify-threshold threshold)
    (ok threshold)
  )
)

;; Emergency reputation override
(define-public (override-reputation 
  (phantom-id (buff 32)) 
  (new-reputation uint))
  (let (
    (phantom-data (unwrap! (map-get? phantom-vault { phantom-hash: phantom-id }) ERR-PHANTOM-NOT-FOUND))
  )
    (asserts! (is-eq tx-sender admin) ERR-ACCESS-DENIED)
    (asserts! (<= new-reputation reputation-cap) ERR-INVALID-PARAMS)
    
    (map-set phantom-vault
      { phantom-hash: phantom-id }
      (merge phantom-data { reputation-score: new-reputation })
    )
    
    (ok new-reputation)
  )
)