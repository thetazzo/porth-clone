
if exists("b:current_syntax")
    finish
endif

highlight Yellow      guifg=#ffee71 guibg=None
highlight Orange      guifg=#EEBB00 guibg=None
highlight OrangeBold  guifg=#A8CC99 gui=bold
highlight Cyan        guifg=#00AAFF guibg=None
highlight Pink        guifg=#da519a guibg=None
highlight LightBlue   guifg=#99a9d6 guibg=None
highlight Green       guifg=#03C04A guibg=None

highlight link P_INCLUDE OrangeBold

syntax keyword porthTodo TODO XXX FIXME NOTE

" Keywords
syntax keyword porthKeyword end while do if else proc const assert in 
syntax keyword porthMemory  memory
syntax keyword porthOffset  offset
syntax keyword porthReset   reset
syntax keyword porthInclude include

" Comments
syntax region porthComment start="//" end="$" contains=porthTodo 

" Strings
syntax region porthString start=/\v"/ skip=/\v\\./ end=/\v"/
syntax region porthString start=/\v'/ skip=/\v\\./ end=/\v'/

" Set highlights
highlight default link porthTodo Todo

highlight default link porthKeyword Keyword
highlight default link porthMemory  Cyan
highlight default link porthOffset  LightBlue
highlight default link porthReset   Pink
highlight default link porthInclude OrangeBold

highlight default link porthComment Comment
highlight default link porthString String

let b:current_syntax = "porth"
