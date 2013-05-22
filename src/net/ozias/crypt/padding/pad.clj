;; ## Pad Protocol
;; Pad protocol definition and some useful functions across 
;; all padding implementations
(ns ^{:author "Jason Ozias"}
    net.ozias.crypt.padding.pad)

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
;; This function takes an array of bytes and pads those bytes to the 
;; appropriate blocksize as defined by the given cipher.  This
;; function should evaluate to a vector of 32-bit words.
;;
;; #### unpad
;; This function take a vector of 32-bit words an removes any padding
;; from the vector.  This function should evalutate to an array of 
;; bytes.
;; 
(defprotocol Pad
  (pad [_ unpadded cipher])
  (unpad [_ padded cipher]))
