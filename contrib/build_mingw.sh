#!/bin/sh

# Определяем архитектуру.
if [ $MSYSTEM == MINGW64 ]; then
	export arch="win64"
elif [ $MSYSTEM == MINGW32 ]; then
	export arch="win32"
else 
	echo "Не могу понять, какая у вас архитектура, используемая для сборки.";
	echo "Вы точно запустили скрипт в оболочке MSYS2 MinGW [64/32]-bit ?";
	echo "Обычно его можно запустить выполнив c:\msys64\mingw64.exe или c:\msys64\mingw32.exe";
	exit 1;
fi;

# Задаём переменной contrib текущий путь и переходим на уровень выше.
export contrib=$PWD
cd ..

# Очистка от предыдущей сборки (на всякий случай =) ).
make clean >> /dev/null

# Обновляем репозиторий, и получаем хеш последнего коммита.
echo "Получаем обновления из репозитория.";
git pull
if [ "$?" != 0 ]; then
	echo "Не удалось обновить локальный репозиторий.";
	echo "Вы точно запустили скрипт в папке репозитория?";
	exit 1;
fi;

export commit=$(git rev-parse --verify HEAD | cut -c -7)
if [ -z commit ]; then
	echo "Не удалось получить хеш последнего коммита.";
	echo "Вы точно запустили скрипт в папке репозитория?";
	exit 1;
fi;

# Получаем версию приложения
export version=$(grep -E "I2PD_VERSION_(MAJOR|MINOR|MICRO)\ " version.h | grep -oE '[^ ]+$' | tr '\n' '.'|head -c -1)

echo "Собираем i2pd ${version} (коммит ${commit}) для ${arch}.";

# Собираем приложение с разными параметрами, и архивируем в zip архивы.
make USE_UPNP=yes USE_AVX=1 USE_AESNI=1 -j $NUMBER_OF_PROCESSORS > ${contrib}/build_avx_aesni.log 2>&1
if [ "$?" != 0 ]; then
	echo "Сборка не удалась. Смотрите в build_avx_aesni.log";
	exit 1;
fi;
zip -9 ${contrib}/i2pd_${version}_${commit}_${arch}_mingw_avx_aesni.zip i2pd.exe
make clean >> /dev/null

make USE_UPNP=yes USE_AVX=1 -j $NUMBER_OF_PROCESSORS > ${contrib}/build_avx.log 2>&1
if [ "$?" != 0 ]; then
	echo "Сборка не удалась. Смотрите в build_avx.log.";
	exit 1;
fi;
zip -9 ${contrib}/i2pd_${version}_${commit}_${arch}_mingw_avx.zip i2pd.exe
make clean >> /dev/null

make USE_UPNP=yes USE_AESNI=1 -j $NUMBER_OF_PROCESSORS > ${contrib}/build_aesni.log 2>&1
if [ "$?" != 0 ]; then
	echo "Сборка не удалась. Смотрите в build_aesni.log";
	exit 1;
fi;
zip -9 ${contrib}/i2pd_${version}_${commit}_${arch}_mingw_aesni.zip i2pd.exe
make clean >> /dev/null

make USE_UPNP=yes -j $NUMBER_OF_PROCESSORS > ${contrib}/build.log 2>&1
if [ "$?" != 0 ]; then
	echo "Сборка не удалась. Смотрите в build.log";
	exit 1;
fi;
zip -9 ${contrib}/i2pd_${version}_${commit}_${arch}_mingw.zip i2pd.exe
make clean >> /dev/null

echo "Сборка i2pd ${version} для ${arch} завершена.";
exit 0;
