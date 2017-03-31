Demostrativo de criptografia en Android con AES/128, creacion de credenciales login/password encriptadas con DES 
y generacion simple de passwords


/* Fortaleza del AES-128
 *
 * Un billón de ordenadores que pudieran cada uno probar mil millones de claves por segundo,
 * tardarían más de 2.000 millones de años en dar con una del sistema AES-128,
 * y hay que tener en cuenta que las máquinas actuales sólo pueden probar
 * 10 millones de claves por segundo
 *
 */
 
 /*
 * DES fortaleza
 * En general, DES utiliza una clave simétrica de 64 bits, 
 * de los cuales 56 son usados para la encriptación, mientras que los 8 restantes son de paridad, 
 * y se usan para la detección de errores en el proceso.
 * 
 * Como la clave efectiva es de 56 bits, 
 * son posible un total de 2 elevado a 56 = 72.057.594.037.927.936 claves posibles, 
 * es decir, unos 72.000 billones de claves, 
 * por lo que la ruptura del sistema por fuerza bruta o diccionario es sumamente improbable, 
 * aunque no imposible si se dispone de suerte y una gran potencia de cálculo.
 */
 
 
 Los codigos fueron tomados de diferentes fuentes de Internet, actualizados, completados y adaptados para Android
