GPG 的基本应用
============


GPG_, 即 `GNU Privacy Guard`_ 。


创建一对公私钥
------------

使用 ``gpg --full-gen-key``。


导出自己的公私钥
--------------

公钥
++++

::

   gpg --export -a rectigu@gmail.com > key.pub


发布自己的公钥
************

使用 ``gpg --send-keys``。


私钥
++++

::

   gpg --export-secret-keys -a -o key rectigu@gmail.com

然后将私钥备份到一个隐蔽的、安全的地方。


导入自己的公私钥
--------------


::

   gpg --import key
   gpg --edit-key rectigu@gmail.com
   # gpg> trust
   # Choose ``I trust ultimately``
   # gpg> q


对大文件签名
----------


签名操作其实也是加密过程，所以对大文件的签名通常不是对文件内容，
而是对文件杂凑（使用具有足够强度的密码学杂凑算法计算）。

也就是，先计算文件杂凑，然后对文件杂凑签名。

举个例子。

::

   sha1sum --tag archlinux-2016.04.01-dual.iso | gpg -a --clearsign > archlinux-2016.04.01-dual.iso.sha1sum.asc


.. _GPG: https://www.gnupg.org/
.. _GNU Privacy Guard: GPG_
