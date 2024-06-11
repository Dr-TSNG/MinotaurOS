## 1
/net/socket.rs中

// 创建 inode， 赋值给 生成的 udp socket ， inode的类型为 IFSOCK
// 现在未在 UdpSocket::new()中指定 FileMeta ， new()中设置为None
// 是在这个函数中指定FileMeta ， 还是改变UdpSocket的new，传入FileMeta，
// 以及怎么构造FileMeta并传入socket结构体
```rust
if socket_type.contains(SocketType::SOCK_DGRAM){
    let socket = UdpSocket::new();
    let socket = Arc::new(socket);
    let cur = current_process().inner.lock();
    let file_desc = FileDescriptor::new(socket,flags);
    let fd_num = cur.fd_table.put(file_desc,0).unwrap();
    cur.socket_table.insert(fd_num,socket);
    Ok(fd_num as usize)
}
```
需要创建文件句柄，关于inode中 /fs/devfs/net.rs怎么和文件系统结合的问题。

