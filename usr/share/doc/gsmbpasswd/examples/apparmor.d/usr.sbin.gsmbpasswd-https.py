# Last Modified: Tue Dec  2 16:40:30 2014
#include <tunables/global>

/usr/sbin/gsmbpasswd-https.py {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/python>
  #include <abstractions/ssl_certs>
  #include <abstractions/ssl_keys>



  /bin/dash Cx,
  /etc/gsmbpasswd/certs/* r,
  /etc/gsmbpasswd/gsmbpasswd-html.conf r,
  /etc/gsmbpasswd/gsmbpasswd-messages.conf r,
  /etc/gsmbpasswd/gsmbpasswd.conf r,
  /etc/gsmbpasswd/private/* r,
  /etc/gsmbpasswd/public/static/* r,
  /etc/gsmbpasswd/public/templates/ r,
  /etc/gsmbpasswd/public/templates/index.html r,
  /etc/mime.types r,
  /run/gsmbpasswd/sessions/ r,
  /run/gsmbpasswd/sessions/* rw,
  /usr/bin/smbpasswd Cx,
  /usr/sbin/gsmbpasswd-https.py r,
  /usr/sbin/gsmbpasswd-https.pyc rw,
  /var/log/gsmbpasswd/ r,
  /var/log/gsmbpasswd/* rw,
  @{PROC}/*/fd/ r,
  @{PROC}/*/mounts r,


  profile /bin/dash {
    #include <abstractions/base>


    /sbin/ldconfig rix,

  }

  profile /usr/bin/smbpasswd {
    #include <abstractions/base>
    #include <abstractions/nameservice>
    #include <abstractions/samba>


    /usr/bin/smbpasswd r,

  }
}
