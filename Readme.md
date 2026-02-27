libBLS: una biblioteca C ++ para firmas de umbral BLS
Estado de la construcción codecov Mejores prácticas de CII Discordia

Una biblioteca matemática escrita en C ++ que admite firmas de umbral BLS, generación de clave distribuida (DKG) y cifrado de umbral (TE).

Esta biblioteca libBLS está desarrollada por SKALE Labs y utiliza la biblioteca libff y PBC de SCIPR-LAB de Ben Lynn (consulte Bibliotecas a continuación).

Una nota importante sobre la preparación para la producción
Esta biblioteca libBLS aún se encuentra en desarrollo activo y, por lo tanto, debe considerarse como software alfa . El desarrollo aún está sujeto a un endurecimiento de la seguridad, más pruebas y cambios importantes. Esta biblioteca aún no ha sido revisada ni auditada por seguridad. Consulte SECURITY.md para conocer las políticas de informes.

Visión general
libBLS es una biblioteca C ++ para firmas BLS y DKG que admite firmas de umbral y firmas múltiples. También es compatible con el cifrado de umbral .

El proceso de firma procede en 4 pasos:

Generación de claves
Hashing
Firma
Verificación
libBLS utiliza la curva elíptica alt_bn128 (curva de Barreto-Naehrig) para ser compatible con la criptografía de Ethereum y proporciona 128 bits de seguridad. Además, brinda la oportunidad de generar claves secretas con el algoritmo DKG que admite la misma curva.

libBLS en su mayor parte corresponde al estándar de firma BLS . Este trabajo aún está en progreso y se mejorará en los próximos meses.

El proceso de cifrado se está ejecutando de la siguiente manera:

Generación de claves
Cifrado
Descifrado
Verificación y combinación de acciones
Puede obtener más información sobre las estructuras algebraicas utilizadas en este algoritmo en la tesis doctoral de Ben Lynn . libBLS utiliza una biblioteca pbc de Ben Lynn modificada con un error de corrupción de memoria corregido y la curva TIPO A para emparejamiento bilineal simétrico.

Especificaciones de rendimiento
libBLS permite firmar alrededor de 3000 mensajes por segundo en un solo hilo (CPU Intel® Core ™ i3-4160 @ 3.60GHz). Sin embargo, para nuestra solución, hemos implementado la firma de tiempo constante (0.01 segundos para la señal) para evitar ataques de tiempo.

requerimientos de instalación
libBLS se ha creado y probado en Ubuntu y Mac.

GitHub se usa para mantener este código fuente. Clona este repositorio de la siguiente manera:

clon de git https://github.com/skalenetwork/libBLS.git
 cd libBLS
Dependencias de edificios
Asegúrese de que estén instalados los paquetes necesarios que se enumeran a continuación.

Construya las dependencias de libBLS mediante:

cd deps
bash ./build.sh
cd ..
Construyendo desde la fuente en Mac
brew install flex bison libtool automake cmake pkg-config yasm
 # Configure el proyecto y cree un directorio de construcción.
cmake -H. -Bbuild

# Construya todos los objetivos predeterminados usando todos los núcleos. 
cmake --build build - -j $ ( sysctl -n hw.ncpu )
Construyendo desde la fuente en Ubuntu
Asegúrese de que los paquetes necesarios estén instalados ejecutando:

sudo apt-get update
sudo apt-get install -y automake cmake build-essential libprocps-dev libtool \
                        pkg-config yasm texinfo autoconf flex bison clang-format-6.0
Configure la compilación del proyecto con los siguientes comandos.

# Configure el proyecto y cree un directorio de construcción.
cmake -H. -Bbuild

# Construya todos los objetivos predeterminados usando todos los núcleos. 
cmake --build build - -j $ ( nproc )
Incluir la biblioteca
# incluye  < libBLS.h >
Documentación
Consulte los documentos para obtener la documentación de libBLS.

Bibliotecas
libff por SCIPR-LAB
pbc de Ben Lynn con modificaciones de SKALE Labs
Contribuyendo
Si tiene alguna pregunta, consulte a la comunidad de desarrollo en Discord .

Discordia

De lo contrario, consulte nuestro CONTRIBUTING.md para obtener más información.

Licencia
Licencia

Copyright (C) 2018-presente SKALE Labs
