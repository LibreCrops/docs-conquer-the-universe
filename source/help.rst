基本帮助
========


1. 如何寻求机器的帮助
---------------------


本文档所说的 ``机器的帮助`` 指的是自包含的 **离线** 文档。


1.1. 命令行
+++++++++++

1.1.1. 内置帮助
***************

- 外部命令

  UNIX_ / POSIX_ / Linux_ 环境下的命令行程序如果不提供 ``--help`` ，
  都是耍流氓，
  比如说 OpenSSH_ 提供的 ``ssh``, ``ssh-keygen``, ``ssh-add``
  与 ``ssh-agent`` 等命令，全都耍流氓。
  （的确，他们收到 ``--help`` 的时候会显示简要的使用信息，
  然而那是因为他们不认得 ``--help`` ，
  而不是因为他们提供了 ``--help`` 。
  毕竟 OpenSSH_ 是 BSD_ 风格的程序。我喜欢 GNU_ 风格的程序。）


- Bash_

  使用 ``help`` 内置命令查看内置命令的帮助。

- Zsh_

  使用 ``run-help`` 函数查看各种帮助，包括内置命令、man 手册等。
  其快捷键为 ``M-h`` 。


1.1.2. 外部帮助
***************

- man_

  man_ 手册需要安装，
  不过，通常在安装系统的时候会安装上一套 `基本的 man 手册`_ 。
  然后，在安装其他程序的时候，他们的 man_ 手册也会一起安装上，
  或者说，程序自带自己的 man_ 手册。

  .. _基本的 man 手册: https://www.kernel.org/doc/man-pages/


- info_

  info_ 手册也需要安装，不过通常是跟程序一起安装的，
  或者说，是程序自带的。

  GNU_ 的程序大都使用这种文档方式，比如 Bash_ 。

  不带参数执行 info_ 可以看到总目录。

  注意：要想愉快地使用 info_ ，你需要花点时间了解一下它的工作方式。


1.2. 编程语言
+++++++++++++

1.2.1. Python
*************

Python_ 编程语言自包含的帮助也就是写在 Docstring_ 里面的文档。

`pydoc`_ 可以用来查看这些自带的文档，
尽管不是特别详细（你可以指望 Python_
包的开发者会把 Docstring_ 写得特别详细），
但是完全可以胜任大多数情况，尤其是在没有网络的情况下。

在 Windows 环境下你可能额外需要配置，或者使用 ``python -m pydoc`` 。
另外， Python_ 的 Windows 发行自带了一份 CHM_ 格式的详细的文档。

例如。

查看 pathlib2_ 模块 Path 类自带的文档。
注意这个模块不属于 Python_ 标准库。

::

   pydoc2 pathlib2.Path

查看 GitPython_ 模块 Remote 类自带的文档。
注意这个模块不属于 Python_ 标准库。

::

   pydoc3 git.Remote

查看 Python_ 标准库 `re`_ 模块自带的文档。
尽管自带的文档比不上在线文档详细，
但是很多没记牢的东西都可以看到。

::

   python -m pydoc re

.. _Python: https://www.python.org/
.. _pydoc: https://docs.python.org/3/library/pydoc.html
.. _Docstring: https://en.wikipedia.org/wiki/Docstring
.. _CHM: https://en.wikipedia.org/wiki/Microsoft_Compiled_HTML_Help
.. _pathlib2: https://github.com/mcmtroffaes/pathlib2
.. _GitPython: https://github.com/gitpython-developers/GitPython
.. _re: https://docs.python.org/3/library/re.html
.. _Bash: https://www.gnu.org/software/bash/
.. _Zsh: http://www.zsh.org/
.. _man: https://en.wikipedia.org/wiki/Man_page
.. _info: https://en.wikipedia.org/wiki/Info_(Unix)
.. _UNIX: https://en.wikipedia.org/wiki/Unix
.. _POSIX: https://en.wikipedia.org/wiki/POSIX
.. _Linux: https://en.wikipedia.org/wiki/Linux
.. _OpenSSH: http://www.openssh.com/
.. _BSD: https://en.wikipedia.org/wiki/Berkeley_Software_Distribution
.. _GNU: https://en.wikipedia.org/wiki/GNU_Project


2. 如何寻求人类的帮助
---------------------
