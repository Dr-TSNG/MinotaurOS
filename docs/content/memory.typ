#import "../components/prelude.typ": *

= 内存管理模块实现

== 内存布局

MinotaurOS 使用单一页表结构，内存布局如#[@fig:内存布局]所示。在本系统中，内核例程与用户例程处于同一页表下：内核区域位于虚拟地址高位，用户区域位于虚拟地址低位。为了方便在内核进行地址转换，从内核镜像开始到可用内存的最大地址的物理内存都按照固定偏移映射到虚拟内存。因此在一个页表结构下，可能存在两个页表项指向同一个物理页帧。这样的设计最大的方便之处在于通过物理页号访问内存时，可以无需经过页表翻译，直接通过偏移得到虚拟地址，利于构造页目录帧和写时复制。

#figure(
  image("img/内存布局.png", width: 80%),
  caption: [MinotaurOS 内存布局],
  supplement: [图],
)<内存布局>

== 堆分配器和用户页帧分配器

MinotaurOS 存在两个内存分配器，分别是堆分配器和用户页帧分配器。堆分配器用于分配内核堆，即内存布局中位于内核镜像区域的内存，其分配的页帧始终位于所有页表的全局映射区域。用户页帧分配器分配内存布局中位于可用内存区域的内存，其分配的页帧也存在于页表的全局映射区域（可以通过偏移直接访问），但是可能被同时映射到用户空间的虚拟地址。

堆分配器和用户页帧分配器使用相同的数据结构保存（如#[@lst:分配器结构]所示），但在实现上不同。堆分配器使用 Buddy System 算法，用户页帧分配器使用线性分配回收算法。堆分配器和用户页帧分配器均使用 RAII 方式实现自动回收，即使用帧跟踪器的数据结构跟踪分配的内存。当帧跟踪器被析构时，自动执行回收操作。

#code-figure(
  ```rs
  pub struct HeapFrameTracker /* UserFrameTracker */ {
      pub ppn: PhysPageNum,
      pub pages: usize,
  }
  ```,
  caption: [分配器结构],
  label-name: "分配器结构",
)

== 虚拟内存数据结构

一个虚拟地址空间由一个`AddressSpace`对象描述（如#[@lst:AddressSpace对象]所示）。`AddressSpace`对象包含了根页表、ASID、区域映射表和页表帧数组。其中，区域映射表是 MinotaurOS 虚拟内存系统的核心数据结构，描述了虚拟地址空间的区域。不同的区域可能有不同的映射方式，例如线性映射、共享内存、写时复制等。页表帧数组用于存储页表帧的跟踪器。

#code-figure(
  ```rs
  pub struct AddressSpace {
      /// 根页表
      pub root_pt: PageTable,

      /// 与地址空间关联的 ASID
      asid: ASID,

      /// 地址空间中的区域
      regions: BTreeMap<VirtPageNum, Box<dyn ASRegion>>,

      /// 该地址空间关联的页表帧
      pt_dirs: Vec<HeapFrameTracker>,
  }
  ```,
  caption: [AddressSpace 对象],
  label-name: "AddressSpace对象",
)

== 虚拟地址空间区域实现

MinotaurOS 的虚拟地址空间区域通过`ASRegion`接口定义（如#[@lst:ASRegion接口]所示）。`ASRegion`定义了虚拟地址空间区域的基本操作，包括获取元数据、映射、解映射、复制和错误处理程序。目前为止，MinotaurOS 实现了`DirectRegion`、`LazyRegion`、`FileRegion`三种区域类型。其中，`DirectRegion`用于内核空间的全局映射；`LazyRegion`用于用户空间的页，实现了写时复制；`FileRegion`用于文件映射。

地址空间区域元数据`ASRegionMeta`存储了区域的基本信息，包括区域的名称、起始地址、大小和权限。每个`ASRegion`对象都需要实现`metadata`方法，返回一个`ASRegionMeta`对象的引用。为了与整体地址空间解耦，`ASRegion`及其元数据不存储页表帧和根页表，而是要求映射和解映射等操作所需的根页表在调用时传入，并将映射过程产生的页表帧委托给上层的`AddressSpace`管理。因此，虽然一个地址空间区域必然包含在一个地址空间中，但是地址空间区域并不与特定的地址空间绑定。这方便了地址空间区域的复制和移动。

#code-figure(
  ```rs
  pub trait ASRegion: Send + Sync {
      /// 区域元数据
      fn metadata(&self) -> &ASRegionMeta;

      /// 将区域映射到页表，返回创建的页表帧
      fn map(&self, root_pt: PageTable, overwrite: bool)
          -> Vec<HeapFrameTracker>;

      /// 将区域取消映射到页表
      fn unmap(&self, root_pt: PageTable);

      /// 调整区域大小
      fn resize(&mut self, new_pages: usize);

      /// 拷贝区域
      fn fork(&mut self, parent_pt: PageTable)
          -> Box<dyn ASRegion>;

      /// 同步区域
      fn sync(&self) {}

      /// 错误处理
      fn fault_handler(&mut self, pt: PageTable, vpn: VirtPageNum)
          -> SyscallResult;
  }
  ```,
  caption: [ASRegion 接口],
  label-name: "ASRegion接口",
)

=== 直接映射区域

`DirectRegion`采用线性映射，仅记录对应页的物理页号和权限。在映射到页表时，通过将物理页号加上固定的偏移，直接得到对应的虚拟页号。`DirectRegion`的页表权限始终与区域权限保持一致。复制区域时，直接复制记录的字面值即可。同时，无需额外的错误处理程序。

=== 懒惰映射区域

`LazyRegion`为区域内的每一个虚拟页存储了一个`PageState`对象（如#[@lst:PageState对象]所示）。一个虚拟页可能存在三种状态：未分配、已映射和写时复制。若虚拟页处于未分配状态，则对应的`PageState`无需存储额外信息；若虚拟页处于已映射状态，则其独占持有一个用户页帧跟踪器；若虚拟页处于写时复制状态，则与其他区域（可能存在于不同的地址空间）共享持有一个用户页帧跟踪器。

#code-figure(
  ```rs
  enum PageState {
      /// 页面为空，未分配物理页帧
      Free,
      /// 页面已映射
      Framed(UserFrameTracker),
      /// 写时复制
      CopyOnWrite(Arc<UserFrameTracker>),
  }
  ```,
  caption: [PageState 对象],
  label-name: "PageState对象",
)

#h(2em) 将`LazyRegion`映射到页表时，根据每一个虚拟页的状态不同，映射到页表上的对应页表项的权限也不同。即页表项权限与区域的权限并不一定保持一致。页表项映射规则如#[@algo:LazyRegion页表映射]所示：

（1）若虚拟页处于未分配状态，则对应页表项的权限为空；

（2）若虚拟页处于已映射状态，则对应页表项的权限与区域权限保持一致；

（3）若虚拟页处于写时复制状态，则对应页表项的权限为只读。

#algorithm-figure(
  pseudocode(
    no-number,
    [*input:* page],
    [*if* page.state = Free *then*], ind,
    [page.pte $<-$ empty], ded,
    [*else if* page.state = Framed *then*], ind,
    [page.pte $<-$ region.perm], ded,
    [*else* page.state = CopyOnWrite *then*], ind,
    [page.pte $<-$ region.perm - Write], ded,
    [*end*],
  ),
  caption: [LazyRegion 页表映射],
  label-name: "LazyRegion页表映射",
)

#h(2em) 当虚拟页处于写时复制状态时，若发生写操作，会触发 Page Fault。无论 Page Fault 发生在内核态还是用户态，MinotaurOS 都会在 Trap 中调用对应区域的错误处理程序，如#[@algo:LazyRegion错误处理]所示。`LazyRegion`的错误处理程序会将写时复制页的状态转换为已映射，并分配一个新的用户页帧，将原有的用户页内容复制到新的用户页上，再将页表项权限调整为与区域一致。这样，写时复制的区域就变成了独占持有一个用户页帧跟踪器，不再与其他区域共享。

#algorithm-figure(
  pseudocode(
    no-number,
    [*input:* page],
    [*if* page.state = Free *then*], ind,
    [page.frame $<-$ *alloc_frame*()],
    [page.state $<-$ Framed], ded,
    [*else if* page.state = CopyOnWrite *then*], ind,
    [new_frame $<-$ *alloc_frame*()],
    [*copy_frame*(new_frame, page.frame)],
    [page.frame $<-$ new_frame],
    [page.state $<-$ Framed], ded,
    [*end*],
    [*remap*(page)],
  ),
  caption: [LazyRegion 错误处理],
  label-name: "LazyRegion错误处理",
)

#h(2em) 当对整个区域进行复制时，`AddressSpace`会调用`fork`方法，如#[@algo:LazyRegion复制]所示。`LazyRegion`会将当前区域已映射的虚拟页和复制区域对应的页状态都设置为写时复制，指向同一个物理页，再将页表项权限调整为只读。这样，原区域与复制出来的区域共享持有一个用户页帧跟踪器，直到下次发生写操作。

#algorithm-figure(
  pseudocode(
    no-number,
    [*input:* region],
    no-number,
    [*output:* new_region],
    [*for each* page *in* region *do*], ind,
    [*if* page.state = Free *then*], ind,
    [new_page.frame $<-$ empty],
    [new_page.state $<-$ Free], ded,
    [*else if* page.state = Framed *then*], ind,
    [new_page.frame $<-$ page.frame],
    [new_page.state $<-$ CopyOnWrite],
    [page.state $<-$ CopyOnWrite], ded,
    [*else* page.state = CopyOnWrite *then*], ind,
    [new_page.frame $<-$ page.frame],
    [new_page.state $<-$ CopyOnWrite],
    [new_region.*push*(new_page)], ded,
    [*end*],
    [*remap*(page)], ded,
    [*end*],
  ),
  caption: [LazyRegion 复制],
  label-name: "LazyRegion复制",
)

#h(2em) 通过上述设计，MinotaurOS 能够在创建进程时实现写时复制，减少复制开销；同时允许了程序申请巨大的内存空间，而不会立即分配物理页帧，提高了内存分配的效率。

#pagebreak()
