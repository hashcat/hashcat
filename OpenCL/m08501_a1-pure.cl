

#error RACF-KDFAES mode is not implemented for combinations of words, because it only supports passwords up to length 8. \
  If you want to use this mode for a combination attack anyway, consider running something like: \
  hashcat --stdout -a 1 dict1 dict2 > combinations.dict; hashcat -a 0 -m 8501 hashlist combinations.dict

// RACF-KDFAES does not support passwords longer than 8 chars? *facepalm*
