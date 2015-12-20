@echo off
convert Itoopie.svg ^
  -fuzz 90%% -fill transparent -floodfill 2x2 white -fuzz 20%% -fill #AE0E99 -opaque red ^
  -fill #FBBC11 -opaque yellow ^
  ( -clone 0 -resize 256x256  ) ^
  ( -clone 0 -resize 128x128  ) ^
  ( -clone 0 -resize  64x64   ) ^
  ( -clone 0 -resize  48x48   ) ^
  ( -clone 0 -resize  32x32   ) ^
  ( -clone 0 -resize  24x24   ) ^
  ( -clone 0 -resize  16x16   ) ^
  ( -size 150x57 xc:white -clone 0 -geometry 57x57+46+0 -composite -gravity center -write BMP3:ictoopie.bmp +delete ) ^
  ( -clone 0 -write Itoopie_purple.png +delete ) ^
  -delete 0 ictoopie.ico
