set -e -x

base_url='http://repo.msys2.org/msys/x86_64/'
packages="libzstd-1.4.4-2-x86_64.pkg.tar.xz pacman-5.2.1-6-x86_64.pkg.tar.xz zstd-1.4.4-2-x86_64.pkg.tar.xz"
for p in $packages
do
    curl "${base_url}$p" -o "$p"
done
pacman -U --noconfirm $packages
rm -f $packages
