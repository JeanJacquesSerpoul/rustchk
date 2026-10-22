; Intégration à l'explorateur : entrée « Vérifier le checksum » dans le menu contextuel des fichiers.
; Doit rester identique à src-tauri/src/shell.rs (clé de registre et libellés FR/EN).
; Le libellé suit la langue choisie dans l'installeur ; l'application le met à jour quand
; on change de langue dans ses réglages.
!macro NSIS_HOOK_POSTINSTALL
  Push $0
  ${If} $LANGUAGE == ${LANG_FRENCH}
    StrCpy $0 "Vérifier le checksum (RustChk)"
  ${Else}
    StrCpy $0 "Verify checksum (RustChk)"
  ${EndIf}
  WriteRegStr SHCTX "Software\Classes\*\shell\RustChk" "" "$0"
  WriteRegStr SHCTX "Software\Classes\*\shell\RustChk" "Icon" '"$INSTDIR\${MAINBINARYNAME}.exe",0'
  WriteRegStr SHCTX "Software\Classes\*\shell\RustChk\command" "" '"$INSTDIR\${MAINBINARYNAME}.exe" "%1"'
  Pop $0
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  DeleteRegKey SHCTX "Software\Classes\*\shell\RustChk"
!macroend