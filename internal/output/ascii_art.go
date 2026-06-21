// Package output defines shared types and provides rendering helpers across all
// scan modules. It also holds the ANANSI ASCII-art banner used in terminal mode.
package output

// AnansiASCIIArt is the ANSI banner displayed at the start of every terminal
// scan.  It depicts Anansi the spider, a trickster figure from West African
// folklore — fitting for an attack-surface tool.
const AnansiASCIIArt = `
              ;                  &              
            ;;                    ;&            
           ;;;                    ;;;           
      ;    ;;;                    ;;;    ;      
      ;;;  ;;;        ;   ;;      ;;;   ;;;     
      ;;;;  ;;;;   ;;; && ;;;   ;;;;   ;;;;     
       ;;;;   ;;;; ;;;;;;;;;; ;;;;    ;;;;      
         ;;;;;;;;; ;;;;;;;;;;;;;;;; ;;;;;;;;;    
             &;;;;;;;;;;;;$x;;;;;;;;;;;;         
            ;;;;;;;;;;&&&+++&&&;;;;;;;;;;;       
      ;;;;;;;;;  ;;;&&+&&&&&+&&;;;  ;;;;;;;;;;  
      ;;;&    ;; ;;;&+&&&&&&&+&&;;; ;;    &;;;  
      ;;;   ;;;;  ;;;&&+&&&&&&+&;;; ;;;;   ;;;  
      ;;;   ;;;   ;;;;&&++&++++&&;;  ;;;   ;;;  
       ;;   ;;;    ;;;;;;;;;;;&&&&;  ;;;   ;;   
       ;;   ;;;      ;;;;;;;;;;;;;;  ;;;   ;;   
        ;   ;;;        ;;;;;;;;;;    ;;;   ;    
            &;;           ;;;;       ;;&        
              ;;           ;;       ;;;          
                ;                 ;             `
