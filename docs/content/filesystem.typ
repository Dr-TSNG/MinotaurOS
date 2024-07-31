#import "../components/prelude.typ": *

= 文件系统模块

== 挂载命名空间

MinotaurOS 提供了类似 Linux 的挂载命名空间功能。每个进程包含了一个`MountNamespace`引用，`MountNamespace`对象包含一颗挂载树、挂载树的平坦快照和 Inode 缓存。`MountTree`对象包含一个文件系统指针和子树的 map，如#[@lst:挂载命名空间和挂载树]所示。

#code-figure(
  ```rs
  pub struct MountNamespace {
      pub mnt_ns_id: usize,
      pub caches: [InodeCache; 2],
      inner: Mutex<NSInner>,
  }

  struct NSInner {
      tree: MountTree,
      snapshot: HashMap<usize, (usize, String)>,
  }

  struct MountTree {
      mnt_id: usize,
      fs: Arc<dyn FileSystem>,
      /// 子挂载树，`key` 为挂载路径，以 `/` 开头
      sub_trees: BTreeMap<String, MountTree>,
  }
  ```,
  caption: [挂载命名空间和挂载树],
  label-name: "挂载命名空间和挂载树",
)

== 文件系统

MinotaurOS 实现了类似 Linux 虚拟文件系统功能。为了支持不同类型的文件系统，MinotaurOS 设计了一个通用的接口`FileSystem`。`FileSystem` trait 包含两个方法`metadata`和`root`，分别用于获取文件系统的元数据和根目录`Inode`。文件系统元数据包含了文件系统的唯一标识符、设备号、挂载源、文件系统类型和文件系统标志。文件系统接口定义如#[@lst:文件系统接口]所示。

#code-figure(
  ```rs
  /// 文件系统元数据
  /// 一个文件系统在刚创建时不关联任何挂载点，
  /// 通过 `move_mount` 挂载到命名空间。
  pub struct FileSystemMeta {
      /// 唯一标识符
      fsid: usize,
      /// 设备号
      pub dev: u64,
      /// 挂载源
      pub source: String,
      /// 文件系统类型
      pub fstype: FileSystemType,
      /// 文件系统标志
      pub flags: VfsFlags,
  }

  /// 文件系统
  pub trait FileSystem: Send + Sync {
      /// 文件系统元数据
      fn metadata(&self) -> &FileSystemMeta;
      /// 根 Inode
      fn root(&self) -> Arc<dyn Inode>;
  }
  ```,
  caption: [文件系统接口],
  label-name: "文件系统接口",
)

#h(2em) 文件系统与挂载命名空间在结构上是解耦的，文件系统只关心自己内部的目录结构，而挂载命名空间则负责管理全局的路径抽象。这样的设计使得 MinotaurOS 能够支持更多的文件系统类型，同时也使得文件系统的实现更加简单。

== Inode

Inode 是文件系统的核心结构，其唯一地标识了文件系统中的一个文件或目录。在 MinotaurOS 中，Inode 采用了较为复杂的两层接口组成。内层的 `InodeInternal` 接口定义了文件系统的“物理”操作，即直接在块设备上的读写、创建、删除等。外层的 `Inode` 接口定义了文件系统的“逻辑”操作，即包含了元数据、挂载点、和页缓存下的读写操作等。同时，通过隐藏内部接口，防止不经意间绕过了中间缓存结构，MinotaurOS 保证了文件系统的安全性和封装性。`Inode` 和 `InodeInternal` 接口定义如#[@lst:InodeInternal接口]和#[@lst:Inode接口]所示。

#code-figure(
  ```rs
  #[async_trait]
  pub(super) trait InodeInternal {
    /// 从 `offset` 处读取 `buf`，绕过缓存
    async fn read_direct(&self, buf: &mut [u8], offset: isize)
      -> SyscallResult<isize>

    /// 向 `offset` 处写入 `buf`，绕过缓存
    async fn write_direct(&self, buf: &[u8], offset: isize)
      -> SyscallResult<isize>

    /// 设置文件大小，绕过缓存
    async fn truncate_direct(&self, size: isize)
      -> SyscallResult

    /// 查询目录项
    async fn do_lookup_name(self: Arc<Self>, name: &str)
      -> SyscallResult<Arc<dyn Inode>>

    /// 查询目录项
    async fn do_lookup_idx(self: Arc<Self>, idx: usize)
      -> SyscallResult<Arc<dyn Inode>>

    /// 在当前目录下创建文件/目录
    async fn do_create(self: Arc<Self>, mode: InodeMode, name: &str)
      -> SyscallResult<Arc<dyn Inode>>

    /// 在当前目录下创建符号链接
    async fn do_symlink(self: Arc<Self>, name: &str, target: &str)
      -> SyscallResult

    /// 将文件移动到当前目录下
    async fn do_movein(
        self: Arc<Self>,
        name: &str,
        inode: Arc<dyn Inode>,
    ) -> SyscallResult

    /// 在当前目录下删除文件
    async fn do_unlink(self: Arc<Self>,target: Arc<dyn Inode>)
      -> SyscallResult

    /// 读取符号链接
    async fn do_readlink(self: Arc<Self>)
      -> SyscallResult<String>
  }
  ```,
  caption: [InodeInternal 接口],
  label-name: "InodeInternal接口",
)

#code-figure(
  ```rs
  #[async_trait]
  pub trait Inode: DowncastSync + InodeInternal {
    /// 获取 Inode 元数据
    fn metadata(&self) -> &InodeMeta;

    /// 获取文件系统
    fn file_system(&self) -> Weak<dyn FileSystem>;

    fn ioctl(&self, request: usize, value: usize)
      -> SyscallResult<i32>
  }
  impl_downcast!(sync Inode);
  ```,
  caption: [Inode 接口],
  label-name: "Inode接口",
)

#h(2em) 为了使所有的文件系统能够拥有相同的数据抽象，MinotaurOS 定义了统一的文件元数据结构`InodeMeta`（如#[@lst:InodeMeta]所示）。`InodeMeta`结构包含了文件的基本信息，包括文件的设备号、文件名和路径等。

#code-figure(
  ```rs
  pub struct InodeMeta {
      pub key: usize,
      /// 结点编号
      pub ino: usize,
      /// 结点设备
      pub dev: u64,
      /// 结点类型
      pub mode: InodeMode,
      /// 文件名
      pub name: String,
      /// 文件系统路径
      pub path: String,
      /// 父目录
      pub parent: Option<Weak<dyn Inode>>,
      /// 页面缓存
      pub page_cache: Option<Arc<PageCache>>,
      /// 可变数据
      pub inner: Arc<Mutex<InodeMetaInner>>,
  }
  ```,
  caption: [InodeMeta],
  label-name: "InodeMeta",
)

#h(2em) 会发生变化对象放在了`InodeMetaInner`结构内。特别之处在于，整个结构包含在一个`Arc<Mutex>`中，这是为了实现移动文件的一致性。在移动文件时，需要创建一个新的 Inode。而如果旧 Inode 上尚有未关闭的文件描述符，通过旧 Inode 仍然可以访问到物理的文件。因此，需要将元数据的可变部分放在一个独立的结构中，以便在移动文件时，只需要修改元数据的指针即可。`InodeMetaInner`结构定义如#[@lst:InodeMetaInner]所示。

#code-figure(
  ```rs
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
  caption: [InodeMetaInner],
  label-name: "InodeMetaInner",
)

#h(2em) 值得注意的一点是，Inode 的元数据中包含了父节点的弱引用和挂载点。这是为了支持相对路径的解析。在将一个文件系统挂载加入挂载树的同时，MinotaurOS 会将子文件系统的根结点引用加入到挂载点的元数据中。这样，当解析相对路径时，会首先根据挂载点的元数据找到对应的子文件系统，再在子文件系统中查找；当不存在相应挂载点时，再在当前文件系统中查找。除此之外，另一个特点是`InodeMeta`的文件系统路径仅是相对于该文件系统根目录的路径，而不是相对整个挂载命名空间的路径。

这样的设计使得文件系统与挂载树解耦，并让 MinotaurOS 能够在未来兼容更多的高级文件系统挂载功能，如`chroot`、`move_mount` 等系统调用。目前为止，MinotaurOS 实现了基本的文件系统挂载功能，包括`mount`和`umount`系统调用。

== 文件读写接口 File

`File`接口是对“打开的文件”的抽象。与`Inode`不同，`File`是对文件的操作的抽象，而不是文件对应的物理结点。`File` trait 定义了文件的基本操作，包括读、写、pollin、pollout 等，通常由`Inode`的`open`方法得到。`File`的元数据中包含了一个`Inode`的引用和打开文件的 Flags。文件的类型包括普通文件、目录文件、设备文件、管道和 socket。每种文件类型都有对应的实现，这些实现在不同的文件系统中是通用的。

=== 普通文件

普通文件结构中存储了文件元数据、读写偏移量，以及`pread`、`pwrite`操作的锁，如#[@lst:RegularFile]所示。普通文件实现了`seek`方法，并通过 Inode 的`read`、`write`方法进行具体的读写操作。

#code-figure(
  ```rs
    pub struct RegularFile {
        metadata: FileMeta,
        pos: AsyncMutex<isize>,
        prw_lock: AsyncMutex<()>,
    }
  ```,
  caption: [RegularFile],
  label-name: "RegularFile",
)

=== 目录文件

目录文件结构中存储了文件元数据和读写偏移量。目录文件实现了`readdir`方法，用于读取目录项，如#[@lst:DirFile]所示。值得注意的是，MinotaurOS 不将“.”和“..”作为独立的 Inode 存储，而是将读取目录时的 0 号和 1 号直接指向自身和父目录。这是因为 Inode 是树型结构，需要防止出现循环引用。

#code-figure(
  ```rs
  pub struct DirFile {
      metadata: FileMeta,
      pos: AsyncMutex<usize>,
  }

  async fn readdir(&self)
    -> SyscallResult<Option<(usize, Arc<dyn Inode>)>> {
      let inode = self.metadata.inode.as_ref().unwrap();
      let mut pos = self.pos.lock().await;
      let inode = match *pos {
          0 => inode.clone(),
          1 => inode.metadata().parent.clone()
                   .and_then(|p| p.upgrade())
                   .unwrap_or(inode.clone()),
          _ => match inode.clone().lookup_idx(*pos - 2).await {
              Ok(inode) => inode,
              Err(Errno::ENOENT) => return Ok(None),
              Err(e) => return Err(e),
          },
      };
      *pos += 1;
      Ok(Some((*pos - 1, inode)))
  }
  ```,
  caption: [DirFile],
  label-name: "DirFile",
)

#pagebreak()

=== 设备文件

字符设备和块设备文件仅包含文件元数据，并将读写和 ioctl 操作委托给对应的设备驱动。

=== 管道

管道（Pipe）是一种特殊的文件，用于进程间通信。管道的读写两端由相同的数据结构构成，如#[@lst:Pipe]所示。管道结构中包含了文件元数据、读写标志、另一端的弱引用和内部数据结构。内部数据结构包含了缓冲区、已传输的字节数和读写等待队列。管道的两端共用一个内部数据结构，通过读写标志区分读写操作。

#code-figure(
  ```rs
  pub struct Pipe {
      metadata: FileMeta,
      is_reader: bool,
      other: LateInit<Weak<Pipe>>,
      inner: Arc<Mutex<PipeInner>>,
  }

  #[derive(Default)]
  struct PipeInner {
      buf: VecDeque<u8>,
      transfer: usize,
      readers: VecDeque<Waker>,
      writers: VecDeque<Waker>,
  }
  ```,
  caption: "Pipe",
  label-name: "Pipe",
)

#h(2em) 管道没有关联的 Inode，它的读写由专门的管道函数处理。管道的读写操作是异步的，读写两端分别通过`PipeReadFuture`和`PipeWriteFuture`实现异步读写操作。以`PipeReadFuture`为例：该结构中包含了管道对象的引用、系统调用的缓冲区和读取位置。`PipeReadFuture`实现了`Future` trait，通过`poll`方法实现了管道的异步读取操作。当管道缓冲区中有数据时，将数据读取到系统调用的缓冲区中，并唤醒等待的写者；当缓冲区为空时，将当前读者加入到等待队列中，等待写者唤醒；当管道的另一端被关闭时，返回读取的字节数为 0。

#code-figure(
  ```rs
  struct PipeReadFuture<'a> {
      pipe: &'a Pipe,
      buf: &'a mut [u8],
      pos: usize,
  }
  ```,
  caption: [PipeReadFuture],
  label-name: "PipeReadFuture",
)

#code-figure(
  ```rs
  impl Future for PipeReadFuture<'_> {
    type Output = SyscallResult<isize>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>)
      -> Poll<Self::Output> {
      let mut inner = self.pipe.inner.lock();
      let read = min(self.buf.len() - self.pos, inner.buf.len());
      if read > 0 {
        for (i, b) in inner.buf.drain(..read).enumerate() {
          self.buf[i] = b;
        }
        self.pos += read;
        inner.transfer += read;
        while let Some(waker) = inner.writers.pop_front() {
          waker.wake();
        }
        Poll::Ready(Ok(read as isize))
      } else {
        if self.pipe.other.strong_count() == 0 {
          return Poll::Ready(Ok(0));
        }
        inner.readers.push_back(cx.waker().clone());
        Poll::Pending
      }
    }
  }
  ```,
  caption: [PipeReadFuture poll],
)

== Inode 缓存

文件系统的访问存在相当的时间局部性，往往存在于绝对路径、父目录和子目录之间。在 Linux 当中，使用了哈希表来加快 Inode 的查找过程。MinotaurOS 也实现了类似的缓存机制。

在 MinotaurOS 中，我们采用了一套查询零拷贝的缓存机制。`MountNamespace`中保存了两个`InodeCache`，分别用于绝对路径和相对路径的解析。`InodeCache`是一个哈希表，键为`HashKey`，值为弱引用的`Inode`。`HashKey`由父节点的 Inode key 和子路径组成，如#[@lst:HashKey]所示。
#code-figure(
  ```rs
  #[derive(Eq, Hash, PartialEq, Clone, Debug)]
  struct HashKey<'a> {
      pub parent_key: usize,
      pub subpath: Cow<'a, str>,
  }

  pub struct InodeCache(Mutex<HashMap<
      HashKey<'static>,
      Weak<dyn Inode>,
  >>)
  ```,
  caption: [HashKey 和 InodeCache],
  label-name: "HashKey",
)

Inode key 是全局自增的，在不同文件系统中，Inode 可能有相同的 ino，但不会有相同的 key。子路径由一个`Cow`类型的字符串表示，在`HashKey`中，子路径字符串只有在插入缓存时才会被复制构造，而在查询缓存时，子路径字符串作为`Cow::Borrowed`类型从调用者借用，避免了不必要的内存拷贝。

#code-figure(
  ```rs
  // 插入缓存，复制构造
  let hash_key = HashKey::new(parent_key, Cow::Owned(subpath));
  // 查询缓存，零拷贝
  let hash_key = HashKey::new(parent_key, Cow::Borrowed(subpath));
  ```,
  caption: [InodeCache 插入和查询],
)

== 路径解析

@fig:绝对路径解析 是一个路径解析的例子。访问绝对路径从根挂载树开始，依次匹配子树的路径前缀，遍历相应子树，直到最后一颗不包含匹配前缀的子树，然后将路径解析委托给相应文件系统。对于文件系统内部而言，所有的路径解析都是相对于该文件系统的根目录进行的。

#figure(
  image("img/resolve.png"),
  caption: [绝对路径解析],
  supplement: [图],
)<绝对路径解析>

#pagebreak()
