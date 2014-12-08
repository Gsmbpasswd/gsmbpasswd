# Last Modified: Tue Oct 28 00:37:02 2014
#include <tunables/global>

/usr/sbin/gsmbpasswd-http.py {
  #include <abstractions/base>
  #include <abstractions/python>

  /etc/gsmbpasswd/gsmbpasswd.conf r,
  /etc/mime.types r,
  /usr/sbin/gsmbpasswd-http.py r,
  /usr/sbin/gsmbpasswd-http.pyc rw,
}
