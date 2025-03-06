org &100

bdos equ &0005 ; BDOS entry point

start:  ld c,9 ; BDOS function output string
  ld de,msg ; address of msg
  call bdos
  ret

msg: db 'Hello, world!$'

end
