## 1
/net/socket.rs中

// 创建 inode， 赋值给 生成的 udp socket ， inode的类型为 IFSOCK
if socket_type.contains(SocketType::SOCK_DGRAM){
    let socket = UdpSocket::new();
    let socket = Arc::new(socket);
    let cur = current_process().inner.lock();
    // 需要在这里分配一个fd，与生成的socket关联起来
    // let fd = cur.fd_table;
    cur.socket_table.insert(fd,socket);
    Ok(fd)
}
需要创建文件句柄，关于inode中 /fs/devfs/net.rs怎么和文件系统结合的问题。

