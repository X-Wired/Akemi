package ui

import (
	"fmt"
	"strings"
)

func rgb(r, g, b int, s string) string {
	return fmt.Sprintf("\x1b[38;2;%d;%d;%dm%s\x1b[0m", r, g, b, s)
}

func lerp(a, b, t float64) float64 {
	return a + (b-a)*t
}

func gradientColor(stops [][3]int, t float64) (int, int, int) {
	if len(stops) == 0 {
		return 255, 255, 255
	}
	if len(stops) == 1 {
		return stops[0][0], stops[0][1], stops[0][2]
	}
	if t <= 0 {
		return stops[0][0], stops[0][1], stops[0][2]
	}
	if t >= 1 {
		last := stops[len(stops)-1]
		return last[0], last[1], last[2]
	}

	segmentSize := 1.0 / float64(len(stops)-1)
	segment := int(t / segmentSize)
	if segment >= len(stops)-1 {
		segment = len(stops) - 2
	}

	localT := (t - float64(segment)*segmentSize) / segmentSize
	c1 := stops[segment]
	c2 := stops[segment+1]

	r := int(lerp(float64(c1[0]), float64(c2[0]), localT))
	g := int(lerp(float64(c1[1]), float64(c2[1]), localT))
	b := int(lerp(float64(c1[2]), float64(c2[2]), localT))
	return r, g, b
}

func colorizeASCII(ascii string, palette [][3]int, rainbowOffset float64) string {
	lines := strings.Split(ascii, "\n")

	maxLen := 0
	for _, line := range lines {
		if len(line) > maxLen {
			maxLen = len(line)
		}
	}

	var out strings.Builder
	totalLines := len(lines)

	for y, line := range lines {
		for x, ch := range line {
			if ch == ' ' || ch == '\t' {
				out.WriteRune(ch)
				continue
			}

			tx := 0.0
			if maxLen > 1 {
				tx = float64(x) / float64(maxLen-1)
			}
			ty := 0.0
			if totalLines > 1 {
				ty = float64(y) / float64(totalLines-1)
			}

			t := (tx*0.7 + ty*0.3 + rainbowOffset)
			for t > 1 {
				t -= 1
			}
			for t < 0 {
				t += 1
			}

			r, g, b := gradientColor(palette, t)
			out.WriteString(rgb(r, g, b, string(ch)))
		}
		out.WriteByte('\n')
	}

	return out.String()
}

const AkemiASCII = `
                                                                                            
                                                    -@@@                                                                      
                                                      ]#%@                                                                    
                                                      *@: @*                                                                  
                                                      ]##  @                       >@@@                                       
                                                      %%[)  %                  >@@@@@                                          
                                               =@   %@}}[   +                #@  -@                                            
                                              @<  -@#][    ]}@@@@@]  #@+    }: :)@)                                            
                                             @#   @}:--   :=:       [@:-@@ --  [>%<                                            
                                             @[}  @) *>                 *<*+   ]<}@                                            
                                           @  @ }  @+                     -)   )>>@   @                                        
                                            @#       +                         # *@   @}                                       
                                            :<}-<[>     :                    *  *@=  @@-                                       
                                             }@+    ]}=                       ]@#  )]@-                                        
                                         =%#@} =+  >>               *                 @                                        
                                            %]#   <]       *+=*+ }]           +>:-#@@%                                         
                                           @ } * =}      +>=   :-        :   +  @*-                                            
                                           @ @>  *                        -    - )@                                             
                                            +@[                          < -  )[@ <}+                                          
                                             @<+    +                    +< +- ]@@                                              
                                             @[ +>::}                      :]:@#:                                              
                                              @   >+<*                 -  :#@*@                                                
                                                    *@+              :)  [@@::                                                 
                                                      %%            %) +>>                                                     
                                                        @]       ]]=)                                                          
                                                         :}<*<))>  +[                                                          
                                                          =        ]@     -=:                                                  
                                                          }         -@#%#]>>}@@@                                               
                                                          #       ->-           @%                                             
                                               @         #[     >>                #                                            
                                             :@] @    -]>>    *                                                                
                                          @  }  @=   ->                                                                        
                                          @  @@}  @@@}                                       }@-                               
                                         @@@@@ %@@[-       @%                               =@@                                
                                      -++@@#    @@%>     }@@         [                     @  [>                               
                                      )#@@       >#@[    #@   @@@   =@@@-  @@@            @@@@)                                
                                   +: ]@@*]#%@@@@@@@@)   %@  @@   @@@%-}@@  -@@@@@@@@<@@   ]:                                  
                                 [@@}@@@ }@@@@    -@@)   @)@=   -@@   }@]   @@  +@]   @@> )@@                                  
                                    *@#            @+)* #@ #@@  *@@        ]@[   @%   @@  >@#                                  
                                :  @@  <@          @@+ *@[  <@@*  @@@@@@@- @@   @@   @@   @@                                   
                                %<@: @@@          @@  @}       @@@                  }   @%                                     
                             ]@@@@@%                                                                                           
                                                                                                                                                                                
                                    Build 1.0.0 Stable
                                 Codename: "Cyber Huntress"  
                                    Made with love <3    
                                     -Wired, Fuwa & Vo1d
`

func PrintASCIIArtNeon() {
	palette := [][3]int{
		{150, 80, 255},
		{220, 120, 255},
		{90, 110, 255},
		{120, 220, 255},
	}
	fmt.Println("\x1b[40m")
	fmt.Print(colorizeASCII(AkemiASCII, palette, 0.0))
	fmt.Print("\x1b[0m")
}

func PrintASCIIArtRainbow() {
	palette := [][3]int{
		{255, 80, 180},
		{180, 80, 255},
		{90, 110, 255},
		{80, 220, 255},
		{120, 255, 180},
		{255, 220, 80},
		{255, 120, 80},
		{255, 80, 180},
	}
	fmt.Println("\x1b[40m")
	fmt.Print(colorizeASCII(AkemiASCII, palette, 0.08))
	fmt.Print("\x1b[0m")
}
