基本应用
========


1. Parted 的基本应用
--------------------

磁盘分区工具。


2. SSH 的基本应用
-----------------

安全 Shell。


3. tmux 的基本应用
------------------


3.1. 常用命令
+++++++++++++

命令的详细帮助请查看 tmux_ 的 man 手册。

提示：绑定快捷键可以更灵活的操作。


- new-session

  创建会话。

  别名： ``new`` 。

  ::

     tmux new-session -s main


- split-window

  分割窗口成板块，默认垂直分割（ ``-v`` ），使用 ``-h`` 水平分割。

  别名： ``splitw`` 。

  ::

     tmux split-window -h


- kill-pane

  删除板块。

  别名： ``killp`` 。

  ::

     tmux kill-pane


- kill-session

  结束会话。

  ::

     tmux kill-session


.. _tmux: http://tmux.github.io/


4. IRC 的基本应用
-----------------


IRC_, 即 `Internet Relay Chat`_ 。


4.1. 常用 IRC 客户端
++++++++++++++++++++

- ChatZilla_

  Firefox_ 浏览器的 `拓展`_ 。


- Irssi_

  字符界面的聊天程序。


4.2. 常用 IRC 命令
++++++++++++++++++

注意：有些命令在不同的 IRC 客户端可能不太一样。

使用 ``help`` 命令查看详细的使用文档，例如， ``/help join`` 。

=======================    =======================    ========================
操作                        ChatZilla                  Irssi
=======================    =======================    ========================
列举所有命令                 ``/commands``               ``/help``
连接 IRC 服务器             ``/attach freenode``        ``/connect freenode``
加入 IRC 频道               ``/join #librecrops``
-----------------------    ---------------------------------------------------
退出 IRC 频道               ``/leave``                  ``/part``
断开与 IRC 服务器的连接       ``/disconnect``
关闭 IRC 客户端              ``/quit``
=======================    ===================================================


.. _IRC: https://en.wikipedia.org/wiki/Internet_Relay_Chat
.. _Internet Relay Chat: IRC_
.. _ChatZilla: http://chatzilla.hacksrus.com/
.. _Firefox: https://www.mozilla.org/en-US/firefox/
.. _拓展: https://addons.mozilla.org/en-US/firefox/
.. _Irssi: https://irssi.org/


5. GPG 的基本应用
-----------------


GPG_, 即 `GNU Privacy Guard`_ 。


5.1. 创建一对公私钥
+++++++++++++++++++

使用 ``gpg --full-gen-key``。


5.2. 导出自己的公私钥
+++++++++++++++++++++

- 公钥

  ::

     gpg --export -a rectigu@gmail.com > key.pub

- 发布自己的公钥

  使用 ``gpg --send-keys``。

- 私钥

  ::

     gpg --export-secret-keys -a -o key rectigu@gmail.com

  然后将私钥备份到一个隐蔽的、安全的地方。


5.3. 导入自己的公私钥
+++++++++++++++++++++


::

   gpg --import key
   gpg --edit-key rectigu@gmail.com
   # gpg> trust
   # Choose ``I trust ultimately``
   # gpg> q


5.4. 对大文件签名
+++++++++++++++++


签名操作其实也是加密过程，所以对大文件的签名通常不是对文件内容，
而是对文件杂凑（使用具有足够强度的密码学杂凑算法计算）。

也就是，先计算文件杂凑，然后对文件杂凑签名。

举个例子。

::

   sha1sum archlinux-2016.04.01-dual.iso | gpg -a --clearsign > archlinux-2016.04.01-dual.iso.sha1sum.asc


.. _GPG: https://www.gnupg.org/
.. _GNU Privacy Guard: GPG_
