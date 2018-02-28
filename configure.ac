AC_INIT([ctf_ptooie], [1.1.0], [gbr@voidland.org])
AM_INIT_AUTOMAKE([foreign subdir-objects dist-xz])
AC_CONFIG_HEADERS(config.h)


AC_CANONICAL_HOST
case "${host_cpu}-${host_os}" in
    x86_64-linux-gnu)
        ;;
    *)
        AC_MSG_ERROR([This package can be built only for x86-64 GNU/Linux.])
        ;;
esac


AC_PROG_CC([gcc cc])
AC_PROG_CXX([g++ c++])
if test "x${GCC}" != "xyes"
then
    AC_MSG_ERROR([This package requires the GNU C/C++ compiler.])
fi

CFLAGS="-g -O0"


AC_CONFIG_FILES([Makefile])
AC_OUTPUT
