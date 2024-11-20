# pICe - PNG integrity checker
A PNG file integrity checker that verifies compliance with the [PNG Standard v1.2](http://www.libpng.org/pub/png/spec/1.2/PNG-Contents.html).

> [!WARNING]
> pICe is currently work in progress.
> Not all features have been implemented yet and existing features have not been tested thoroughly!

## 👓 Overview

pICe is a lightweight command-line tool designed to validate the output of PNG encoders and inspect the structure of PNG files. It is ideal for:
- Developers working on PNG encoders.
- Debugging and inspecting malformed PNG files.
- Ensuring PNG files comply with the official PNG specification.

## 🔨 Building pICe
Currently, only Linux is supported. To build the project, follow these steps:
```bash
  git clone https://github.com/ElPatriccio/pICe.git
  cd pICe
  make
```
After compilation, the binary will be located in the build directory. You can run it with:
```bash
  ./build/pice <your_image.png>
```

## 🔎 Example
```text
  ./build/pice assets/test.png
  [INFO] Reading file assets/test.png
  ----------------------------------
     pICe - PNG Integrity Checker
  ----------------------------------
  File size: 83173 bytes
  Chunks:
  
  (+) First chunk has to be of type IHDR!
  IHDR
          (+) Length of IHDR data == 13
          (+) Bit depth is one of the following: 1, 2, 4, 8, 16
          (+) Color type is one of the following: 0, 2, 3, 4, 6
          (+) Color type and bit depth match
          (+) Compression method is set to 0
          (+) Filter method is set to 0
          (+) Interlace method is either 0 or 1
  gAMA
  cHRM
  bKGD
  tIME
  IDAT
  IDAT
  IDAT
  tEXt
  tEXt
  IEND
  (+) Last chunk is IEND
  [INFO] The file assets/test.png complies with the PNG standard (v1.2)
  [INFO] 0 errors
```
## 💡 Features
As of now, pICe is able to verify the basic file structure. pICe checks if every standard chunk is at the right place, in the correct order and appears only as often as the standard allows.

## ✏️ Contributing
Contributions are welcome! If you'd like to contribute, feel free to fork this repository and create a pull request.

## 🧾 License
This project is licensed under the [MIT License](https://github.com/ElPatriccio/pICe/blob/main/LICENSE). Feel free to use, modify, and distribute this project.

