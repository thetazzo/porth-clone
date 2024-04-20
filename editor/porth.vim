highlight Yellow      guifg=#ffee71 guibg=None
highlight Orange      guifg=#EEBB00 guibg=None
highlight OrangeBold  guifg=#A8CC99 gui=bold
highlight Cyan        guifg=#00AAFF guibg=None
highlight Pink        guifg=#da519a guibg=None
highlight LightBlue   guifg=#99a9d6 guibg=None
highlight Green       guifg=#03C04A guibg=None

highlight link P_INCLUDE OrangeBold

syntax keyword P_TODO TODO XXX FIXME NOTE

" Keywords
syntax keyword P_KEYWORD end while do if else proc const assert
syntax keyword Cyan      memory
syntax keyword LightBlue offset
syntax keyword Pink      reset
syntax keyword P_INCLUDE include

" Comments
syntax region P_COMMENT_LINE start="//" end="$" contains=P_TODO start=+\(L\|u\|u8\|U\|R\|LR\|u8R\|uR\|UR\)\="+ skip=+\\\\\|\\"+ end=+"+ contains=cSpecial,cFormat,@Spell extend

" Strings
syntax region P_STRING start=/\v"/ skip=/\v\\./ end=/\v"/
syntax region P_STRING start=/\v'/ skip=/\v\\./ end=/\v'/

" Set highlights
highlight default link P_TODO Todo
" highlight default link P_KEYWORD Keyword
highlight link P_KEYWORD Yellow
highlight default link P_COMMENT_LINE Comment
highlight default link P_STRING String
