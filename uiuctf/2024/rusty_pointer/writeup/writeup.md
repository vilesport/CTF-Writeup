- Challenge cho chúng ta tạo, đọc và xóa 2 loại dữ liệu:
    - Rule: nếu tạo sẽ tạo ra 1 freed chunk có size là 0x50
    - Note: nếu tạo sẽ tạo ra 1 chunk có size là 0x50

- Đồng thời challenge cũng leak cho chúng ta 1 địa chỉ trong libc, do đó ta có sẵn libc base từ đầu mà không cần leak
- Có thể thấy nếu chúng ta tạo 1 rule sau đó tạo 1 note thì cả rule và note sẽ cùng trỏ vào 1 vùng nhớ trên heap, do đó có thể dễ dàng tcache poison
- Challenge có ver libc là 2.31, vẫn còn __free_hook và __malloc_hook nên để có thể pop shell thì ta cần ghi đè 1 trong 2

- Hướng giải quyết của mình:
    - Đầu tiên tcache poison để ghi đè __free_hook thành system
    - Sau đó tiến hành free 1 note có nội dung là /bin/sh để gọi free("/bin/sh") - lúc này là system("/bin/sh") từ đó có được shell và lấy flag