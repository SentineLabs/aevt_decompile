# aevt_decompile

  Read the blog post: https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts

  This program provides further decompiling and decoding of a disassembled run-only AppleScript.

  For input, use a text file that is the output of https://github.com/Jinmo/applescript-disassembler
 
  Running this program will create a new file from the input file annotated with:
  
  1. AEVT codes and their human-readable descriptions;
  2. Decoded hard-coded strings;
  3. Decimal conversions of hard-coded hex numbers;
  4. Names of targeted applications.
  
  __Usage__: `aevt_decompile <file>`
  
  where `<file>` is a text file output from the AppleScript-Disassembler.
  
  aevt_decompile writes its output to `~/Desktop/<file>.out`.
  aevt_decompile is non-destructive (i.e., it does not modify the input file).
  
