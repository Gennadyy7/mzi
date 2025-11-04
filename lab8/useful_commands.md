cd lab8

docker build -t jpeg-stego .

docker run -it --rm -v "$(pwd)":/app jpeg-stego python jpeg_steganography.py