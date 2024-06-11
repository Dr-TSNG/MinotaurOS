## 1
/net/socket.rs中

// 可以不为Socket file实现具体的Inode

// 在new的接口中加入metadata
```rust
if socket_type.contains(SocketType::SOCK_DGRAM){
    let socket = UdpSocket::new(。。。);
    let socket = Arc::new(socket);
    let cur = current_process().inner.lock();
    let file_desc = FileDescriptor::new(socket,flags);
    let fd_num = cur.fd_table.put(file_desc,0).unwrap();
    cur.socket_table.insert(fd_num,socket);
    Ok(fd_num as usize)
}
```
需要创建文件句柄，关于inode中 /fs/devfs/net.rs怎么和文件系统结合的问题。

