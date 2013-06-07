;; ## Pad Protocol
;; Pad protocol definition and some useful functions across 
;; all padding implementations
(ns ^{:author "Jason Ozias"}
    org.azjure.padding.pad)

;; ### remaining
;; Calculate the remaining number of bytes to add.
;;
;;     (remaining 2 8)
;;
;; evaluates to 6
;;
;;     (remaining 12 8)
;;
;; evaluates to 4.
(defn remaining [cnt multiple]
  (if (zero? (mod cnt multiple))
    0
    (- multiple (mod cnt multiple))))

;; ### Pad
;; This protocol defines two function
;;
;; #### pad
;; This function takes a vector of bytes and pads those bytes to the 
;; appropriate blocksize as defined by the given cipher.
;;
;; #### unpad
;; This function take a vector of bytes and removes any padding
;; from the vector.
(defprotocol Pad
  (pad [_ bytes cipher])
  (unpad [_ bytes]))
