# Notes

This file contains more speculative ideas about features to implement.

 - IoT-friendly instantiation, e.g. using AES-CMAC + AES-CTR (requires only AES encrypt circuit). This would require 
 introducing a new MacAlgorithm constant. As AES-CMAC only outputs 16 bytes, we would need to iterate it to produce 
 sufficient output material for both the tag and the SIV (16 bytes each).