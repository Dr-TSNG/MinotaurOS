#import "../components/prelude.typ": *

= 文件系统模块

== 块缓存

非 tmpfs 类文件系统往往需要块设备的支持。在前文所述的块设备接口`BlockDevice`的基础上，为了加快 I/O 速度，MinotaurOS 还设计了一个块设备缓存层`BlockCache`。`BlockCache`用于缓存块设备的读写操作，旨在提高文件系统的性能。块缓存使用 LRU 算法进行缓存替换，当缓存满时，会将最近最少使用的块替换出去，如#[@algo:BlockCache读取]所示。

#algorithm-figure(
  pseudocode(
    no-number,
    [*input:* block_id],
    no-number,
    [*output:* buf],
    [block $<-$ *get_cache*(block_id)],
    [*if* block != null *then*], ind,
    [buf $<-$ block], ded,
    [*else*], ind,
    [buf $<-$ *read_block*(block_id)],
    [write_back $<-$ *put_cache*(block_id, buf)],
    [*if* write_back != null *and* write_back.dirty *then*], ind,
    [*write_block*(write_back)], ded,
    [*end*], ded,
    [*end*],
  ),
  caption: [BlockCache读取],
  label-name: "BlockCache读取",
)

== 挂载命名空间

MinotaurOS 提供了类似 Linux 的挂载命名空间功能。每个进程包含了一个`MountNameSpace`引用，`MountNameSpace`对象包含一个`MountTree`。`MountTree`数据结构描述了一颗挂载树，一个`MountTree`对象包含一个文件系统指针和子树的 map。@fig:绝对路径解析 是一个路径解析的例子。访问绝对路径从根挂载树开始，依次匹配子树的路径前缀，遍历相应子树，直到最后一颗不包含匹配前缀的子树，然后将路径解析委托给相应文件系统。对于文件系统内部而言，所有的路径解析都是相对于该文件系统的根目录进行的。

#figure(
  image("img/resolve.png"),
  caption: [绝对路径解析],
  supplement: [图],
)<绝对路径解析>

== 文件系统和 Inode

MinotaurOS 实现了类似 Linux 虚拟文件系统功能。为了支持不同类型的文件系统，MinotaurOS 设计了一个通用的接口`FileSystem`。`FileSystem` trait 只有两个方法`metadata`和`root`，分别用于获取文件系统的元数据和根目录`Inode`，其中文件系统元数据包括文件系统类型和 VFS Flags。

`Inode`接口是文件系统的核心数据结构（如#[@lst:Inode接口]所示），其唯一地标识了文件系统中的一个文件或目录。`Inode` trait 定义了文件的基本操作，包括读、写、创建、删除等。`direct`系函数用于绕过页缓存直接操作块设备或块缓存对应的内容。这类函数作为文件读写操作的原语供页缓存的实现使用。除了`direct`系函数外，还提供了一系列通用的非`direct`函数，其操作逻辑为存在页缓存时从页缓存读写，否则调用`direct`函数。

#code-figure(
  ```rs
  pub trait Inode: Send + Sync {
      /// 获取 Inode 元数据
      fn metadata(&self) -> &InodeMeta;

      /// 打开一个 Inode，返回打开的文件
      fn open(self: Arc<Self>)
          -> SyscallResult<Arc<dyn File>>

      /// 从 `offset` 处读取 `buf`，绕过缓存
      async fn read_direct(&self, buf: &mut [u8], offset: isize)
          -> SyscallResult<isize>

      /// 向 `offset` 处写入 `buf`，绕过缓存
      async fn write_direct(&self, buf: &[u8], offset: isize)
          -> SyscallResult<isize>

      /// 设置文件大小，绕过缓存
      async fn truncate_direct(&self, size: isize)
          -> SyscallResult

      /// 在当前目录下查找文件
      async fn lookup(self: Arc<Self>, name: &str)
          -> SyscallResult<Arc<dyn Inode>>

      /// 列出目录下编号从 `index` 开始的文件
      async fn list(self: Arc<Self>, index: usize)
          -> SyscallResult<Vec<Arc<dyn Inode>>>

      /// 在当前目录下创建文件
      async fn create(self: Arc<Self>, name: &str)
          -> SyscallResult<Arc<dyn Inode>>

      /// 在当前目录下创建目录
      async fn mkdir(self: Arc<Self>, name: &str)
          -> SyscallResult<Arc<dyn Inode>>

      /// 在当前目录下删除文件
      async fn unlink(self: Arc<Self>, name: &str)
          -> SyscallResult
  }
  ```,
  caption: [Inode 接口],
  label-name: "Inode接口",
)

#h(2em) 为了使所有的文件系统能够拥有相同的数据抽象，MinotaurOS 还定义了统一的文件元数据结构`InodeMeta`（如#[@lst:InodeMeta对象]所示）。`InodeMeta`结构包含了文件的基本信息，包括文件类型、大小、权限等。

值得注意的一点是，`InodeMeta`结构中包含了父节点的弱引用和挂载点。这是为了支持相对路径的解析。在将一个文件系统挂载加入挂载树的同时，MinotaurOS 会将子文件系统的根结点引用加入到挂载点的元数据中。这样，当解析相对路径时，会首先根据挂载点的元数据找到对应的子文件系统，再在子文件系统中查找；当不存在相应挂载点时，再在当前文件系统中查找。除此之外，另一个特点是`InodeMeta`的文件系统路径仅是相对于该文件系统根目录的路径，而不是相对整个挂载命名空间的路径。

这样的设计使得文件系统与挂载树解耦，并让 MinotaurOS 能够在未来兼容更多的高级文件系统挂载功能，如`chroot`、`move_mount` 等系统调用，同时，也使得调试更加简单。

#code-figure(
  ```rs
  pub struct InodeMeta {
      /// 结点编号
      pub ino: usize,
      /// 结点设备
      pub dev: usize,
      /// 结点类型
      pub mode: InodeMode,
      /// 文件名
      pub name: String,
      /// 文件系统路径
      pub path: String,
      /// 页面缓存
      pub page_cache: Option<PageCache>,
      /// 可变数据
      pub inner: Mutex<InodeMetaInner>,
  }

  pub struct InodeMetaInner {
      /// uid
      pub uid: usize,
      /// gid
      pub gid: usize,
      /// 硬链接数
      pub nlink: usize,
      /// 访问时间
      pub atime: TimeSpec,
      /// 修改时间
      pub mtime: TimeSpec,
      /// 创建时间
      pub ctime: TimeSpec,
      /// 文件大小
      pub size: isize,
      /// 父目录
      pub parent: Weak<dyn Inode>,
      /// 挂载点
      pub mounts: BTreeMap<String, Arc<dyn Inode>>,
  }
  ```,
  caption: [InodeMeta 对象],
  label-name: "InodeMeta对象",
)

== 文件读写接口 File

`File`接口是对“打开的文件”的抽象。与`Inode`不同，`File`是对文件的操作的抽象，而不是文件对应的物理结点。`File` trait 定义了文件的基本操作，包括读和写等，通常由`Inode`的`open`方法得到。`File` 的元数据中包含了一个`Inode`的引用，prw 读写锁以及文件的偏移量。

#pagebreak()
