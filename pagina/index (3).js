import { neon } from '@neondatabase/serverless';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import express from 'express';
import { engine } from 'express-handlebars';
import bcrypt from 'bcryptjs';

const CLAVE_SECRETA = 'sedavueltaelsemestre123';
const AUTH_COOKIE_NAME = 'segurida';

const sql = neon(
   'postgresql://neondb_owner:KSAIMZi13fmG@ep-bitter-sun-a8419k4e.eastus2.azure.neon.tech/neondb?sslmode=require'
);

const app = express();



app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

app.engine('handlebars', engine());
app.set('view engine', 'handlebars');
app.set('views', './views');

// Middleware de autenticación
const authMiddleware = async (req, res, next) => {
  const token = req.cookies[AUTH_COOKIE_NAME];

  if (!token) {
    console.log('No token found');
    return res.status(401).render('unauthorized', { message: 'No estás autenticado para ver esta página.' });
  }

  try {
    req.user = jwt.verify(token, CLAVE_SECRETA);
    const results = await sql('SELECT * FROM users WHERE id = $1', [req.user.id]);

    if (results.length === 0) {
      console.log('User not found');
      return res.status(401).render('unauthorized', { message: 'Usuario no encontrado.' });
    }

    req.user = results[0];
    req.user.salutation = `Hola ${req.user.name}`;
    console.log('Authenticated user:', req.user);
    next();
  } catch (e) {
    console.error('JWT verification failed:', e);
    res.status(401).render('unauthorized', { message: 'Sesión inválida o expirada. Por favor, inicia sesión nuevamente.' });
  }
};

// Definición de rutas
app.get('/login', (req, res) => {
  const error = req.query.error;
  res.render('login', { error });
});

app.get('/regis', (req, res) => {
  res.render('regis');
});

app.get('/recibos', authMiddleware, async (req, res) => {
  const userId = req.user.id;

  try {
    const receipts = await sql(
      'SELECT r.id, r.product_id, r.quantity, r.fecha, p.name, p.price FROM receipts r JOIN products p ON r.product_id = p.id WHERE r.user_id = $1',
      [userId]
    );

    res.render('recibos', { receipts });
  } catch (error) {
    console.error('Error al obtener recibos:', error);
    res.redirect('/profile?message=error');
  }
});


app.get('/carrito', authMiddleware, async (req, res) => {
  const userId = req.user.id;
  const cartItems = await sql('SELECT p.*, c.quantity FROM products p JOIN cart c ON p.id = c.product_id WHERE c.user_id = $1', [userId]);
  
  const itemsWithTotal = cartItems.map(item => ({
    ...item,
    total: item.price * item.quantity
  }));

  const total = itemsWithTotal.reduce((sum, item) => sum + item.total, 0);

  res.render('carrito', { cartItems: itemsWithTotal, total });
});
// Ruta para crear un cliente
app.post('/admin/clientes/create', authMiddleware, async (req, res) => {
  if (!req.user.is_admin) {
    return res.status(403).send('No tienes permisos de administrador.');
  }

  const { rut_cliente, nombre, correo, telefono } = req.body;

  const query = 'INSERT INTO cliente (rut_cliente, nombre, correo, telefono) VALUES ($1, $2, $3, $4) RETURNING id';
  
  try {
    const results = await sql(query, [rut_cliente, nombre, correo, telefono]);
    res.redirect('/admin'); // Redirige a la página de administración después de crear el cliente
  } catch (error) {
    console.error('Error al crear el cliente:', error);
    res.status(500).send('Error al crear el cliente.');
  }
});


app.get('/', (req, res) => {
  res.render('index');
});

app.post('/login', async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  const query = 'SELECT id, password FROM users WHERE email = $1';
  const results = await sql(query, [email]);
  if (results.length === 0) {
    res.redirect(302, '/login?error=unauthorized');
    return;
  }

  const id = results[0].id;
  const hash = results[0].password;

  if (bcrypt.compareSync(password, hash)) {
    const fiveMinutesFromNowInSeconds = Math.floor(Date.now() / 1000) + 30 * 60;
    const token = jwt.sign(
      { id, exp: fiveMinutesFromNowInSeconds },
      CLAVE_SECRETA
    );

    res.cookie(AUTH_COOKIE_NAME, token, { maxAge: 60 * 30 * 1000 });
    res.redirect(302, '/profile');
    return;
  }

  res.redirect('/login?error=unauthorized');
});

app.post('/regis', async (req, res) => {
  const name = req.body.name;
  const email = req.body.email;
  const password = req.body.password;
  const isAdmin = req.body.is_admin === 'true'; // Convertir el valor del checkbox a booleano

  const hash = bcrypt.hashSync(password, 5);
  const query =
    'INSERT INTO users (name, email, password, wallet, is_admin) VALUES ($1, $2, $3, $4, $5) RETURNING id';

  try {
    const results = await sql(query, [name, email, hash, 0, isAdmin]); // Usar isAdmin en lugar de false
    const id = results[0].id;

    const fiveMinutesFromNowInSeconds = Math.floor(Date.now() / 1000) + 5 * 60;
    const token = jwt.sign(
      { id, exp: fiveMinutesFromNowInSeconds },
      CLAVE_SECRETA
    );

    res.cookie(AUTH_COOKIE_NAME, token, { maxAge: 60 * 5 * 1000 });
    res.redirect(302, '/profile');
  } catch {
    res.render('alreadyRegistered');
  }
});


app.get('/logout', (req, res) => {
  res.cookie(AUTH_COOKIE_NAME, '', { maxAge: 1 });
  res.render('index');
});

app.get('/profile', authMiddleware, async (req, res) => {
  const userId = req.user.id;

  try {
    const user = await sql('SELECT name, email, wallet FROM users WHERE id = $1', [userId]);

    // Asegúrate de que el saldo sea un número
    const wallet = parseFloat(user[0].wallet) || 0; // Usa 0 si el saldo no es válido

    res.render('profile', {
      name: user[0].name,
      email: user[0].email,
      wallet: wallet, // Asegúrate de pasar el valor correcto
      message: req.query.message // Si hay un mensaje, pásalo
    });
  } catch (error) {
    console.error('Error al obtener el perfil:', error);
    res.redirect('/login'); // Redirige o maneja el error adecuadamente
  }
});




app.post('/cart/checkout', authMiddleware, async (req, res) => {
  const userId = req.user.id;

  // Obtiene los artículos del carrito del usuario
  const cartItems = await sql(
    'SELECT p.id AS product_id, p.price, c.quantity FROM products p JOIN cart c ON p.id = c.product_id WHERE c.user_id = $1',
    [userId]
  );

  // Calcula el total
  const total = cartItems.reduce((sum, item) => sum + item.price * item.quantity, 0);
  
  // Obtiene el saldo del usuario
  const user = await sql('SELECT wallet FROM users WHERE id = $1', [userId]);

  // Verifica si hay suficiente saldo
  if (user[0].wallet < total) {
    return res.redirect('/profile?message=Error: Monto excede maximo'); // Redirige con mensaje de error
  }

  try {
    // Inicia una transacción
    await sql('BEGIN');

    // Descuenta el dinero de la billetera del usuario
    await sql('UPDATE users SET wallet = wallet - $1 WHERE id = $2', [total, userId]);

    // Borra los artículos del carrito
    await sql('DELETE FROM cart WHERE user_id = $1', [userId]);

    // Inserta los datos en la tabla receipts
    for (const item of cartItems) {
      await sql(
        'INSERT INTO receipts (user_id, product_id, quantity, fecha) VALUES ($1, $2, $3, CURRENT_TIMESTAMP)',
        [userId, item.product_id, item.quantity]
      );
    }

    // Confirma la transacción
    await sql('COMMIT');

    // Redirige con mensaje de éxito
    res.redirect('/profile?message=Compra realizada con exito! revisa tu boleta en recibos!' );
  } catch (error) {
    // Si hay un error, revierte la transacción
    await sql('ROLLBACK');
    console.error('Error en la compra:', error);
    res.redirect('/profile?message=Tu compra no se pudo realizar :('); // Redirige con mensaje de error
  }
});


app.get('/admin', authMiddleware, async (req, res) => {
  if (!req.user.is_admin) {
    return res.status(403).send('No tienes permisos de administrador.');
  }

  try {
    // Obtener el monto total de ventas
    const totalSalesResult = await sql('SELECT SUM(p.price * r.quantity) AS total FROM receipts r JOIN products p ON r.product_id = p.id');
    const totalSales = totalSalesResult[0].total || 0;

    // Obtener todos los productos
    const products = await sql('SELECT * FROM products');

    // Obtener todos los usuarios de la tabla cliente
    const users = await sql('SELECT * FROM cliente');

    // Obtener el tiempo promedio de las sesiones por usuario
    const tiempoPromedioSesionesResult = await sql(`
      SELECT 
        c.rut_cliente,
        c.nombre,
        ROUND(AVG(hs.minutos_total), 2) AS tiempo_promedio_sesion
      FROM 
        cliente c
      JOIN 
        historial_de_sesiones hs ON c.rut_cliente = hs.rut_cliente
      GROUP BY 
        c.rut_cliente, c.nombre
      ORDER BY 
        tiempo_promedio_sesion DESC;
    `);

    // Consulta SQL para obtener todas las mantenciones realizadas en un mes
    const month = 12; // Por ejemplo, diciembre
    const year = 2024; // El año que deseas consultar
    const mantencionesResult = await sql(`
      SELECT 
        ip.descripcion AS componente,
        ip.estado AS estado_componente,
        hs.fecha AS fecha_mantencion,
        hs.minutos_total AS tiempo_utilizado,
        e.estado AS estado_equipo
      FROM 
        inventario_de_perifericos ip
      JOIN 
        historial_de_sesiones hs ON ip.codigo = hs.codigo
      JOIN 
        equipo e ON ip.codigo = e.codigo
      WHERE 
        EXTRACT(MONTH FROM hs.fecha) = $1
        AND EXTRACT(YEAR FROM hs.fecha) = $2
      ORDER BY 
        hs.fecha DESC;
    `, [month, year]);

    const empleadoMasFaltasResult = await sql(`
      SELECT 
        e.nombre AS empleado,
        COUNT(df.id_falta) AS total_faltas
      FROM 
        dias_faltados df
      JOIN 
        empleado e ON df.rut_empleado = e.rut_empleado
      WHERE 
        df.motivo = 'externo'
      GROUP BY 
        e.nombre
      ORDER BY 
        total_faltas DESC
      LIMIT 1;
    `);
    // Renderizar la vista 'admin' con todos los datos
    res.render('admin', { 
      totalSales, 
      products, 
      users, 
      tiempoPromedioSesiones: tiempoPromedioSesionesResult,
      mantenciones: mantencionesResult,
      empleadoMasFaltas: empleadoMasFaltasResult // Pasar el empleado con más faltas a la vista
    });
  } catch (error) {
    console.error('Error al obtener datos de administración:', error);
    res.redirect('/admin?message=error');
  }
});



app.get('/admin/user', authMiddleware, async (req, res) => {
  if (!req.user.is_admin) {
    return res.status(403).send('No tienes permisos de administrador.');
  }

  const { rut_cliente } = req.query; // Obtener el RUT del cliente desde el query params

  try {
    // Buscar el usuario en la tabla cliente
    const userResult = await sql('SELECT * FROM cliente WHERE rut_cliente = $1', [rut_cliente]);

    if (userResult.length === 0) {
      return res.status(404).send('Usuario no encontrado.');
    }

    // Renderizar la información del usuario encontrado
    const user = userResult[0];
    res.render('user-details', { user });
  } catch (error) {
    console.error('Error al buscar usuario por RUT:', error);
    res.redirect('/admin?message=error');
  }
});

app.get('/admin/payments', authMiddleware, async (req, res) => {
  if (!req.user.is_admin) {
    return res.status(403).send('No tienes permisos de administrador.');
  }

  const { rut_cliente } = req.query;  // Obtener el RUT del cliente desde los query params

  try {
    // Consultar los detalles de los pagos de un cliente en el último mes
    const pagosResult = await sql(`
      SELECT 
        p.rut_cliente, 
        p.fecha_pago, 
        p.monto, 
        hs.codigo, 
        hs.minutos_total
      FROM 
        pago p
      JOIN 
        historial_de_sesiones hs ON p.rut_cliente = hs.rut_cliente
      WHERE 
        p.rut_cliente = $1
        AND EXTRACT(MONTH FROM p.fecha_pago) = EXTRACT(MONTH FROM CURRENT_DATE)
        AND EXTRACT(YEAR FROM p.fecha_pago) = EXTRACT(YEAR FROM CURRENT_DATE)
      ORDER BY 
        p.fecha_pago DESC
    `, [rut_cliente]);

    // Verificar si se encontraron pagos
    if (pagosResult.length === 0) {
      return res.render('payments', { message: 'No se encontraron pagos para este cliente en el último mes.' });
    }

    // Renderizar la vista con los resultados de los pagos
    res.render('payments', { pagos: pagosResult });
  } catch (error) {
    console.error('Error al obtener los pagos:', error);
    res.redirect('/admin?message=error');
  }
});




// Ruta para renderizar la vista de creación de productos
app.get('/products/create', authMiddleware, async (req, res) => {
  if (!req.user.is_admin) {
      return res.status(403).send('No tienes permisos de administrador.');
  }

  res.render('crear'); // Asegúrate de que esta vista exista
});


// Ruta para manejar la creación de un nuevo producto
app.post('/products/create', authMiddleware, async (req, res) => {
  if (!req.user.is_admin) {
      return res.status(403).send('No tienes permisos de administrador.');
  }

  const { name, price, image, stock } = req.body;

  const query = 'INSERT INTO products (name, price, image, stock) VALUES ($1, $2, $3, $4) RETURNING id';
  
  try {
      await sql(query, [name, price, image, stock]);
      res.redirect('/admin'); // Redirige a la página de administración después de crear el producto
  } catch (error) {
      console.error('Error al crear el producto:', error);
      res.status(500).send('Error al crear el producto.');
  }
});


app.post('/products/delete/:id', authMiddleware, async (req, res) => {
  if (!req.user.is_admin) {
    return res.send('No eres admin');
  }

  const id = req.params.id;
  await sql('DELETE FROM products WHERE id = $1', [id]);

  res.redirect('/admin');
});

app.get('/products/edit/:id', authMiddleware, async (req, res) => {
  if (!req.user.is_admin) {
    return res.send('No eres admin');
  }

  const id = req.params.id;
  const results = await sql('SELECT * FROM products WHERE id = $1', [id]);

  if (results.length === 0) {
    return res.status(404).send('Producto no encontrado');
  }

  res.render('editar', { product: results[0] });
});


app.post('/products/edit/:id', authMiddleware, async (req, res) => {
  if (!req.user.is_admin) {
    return res.send('No eres admin');
  }

  const id = req.params.id;
  const { name, price, image, stock } = req.body; // Asegúrate de obtener stock aquí

  try {
    await sql(
      'UPDATE products SET name = $1, price = $2, image = $3, stock = $4 WHERE id = $5',
      [name, price, image, stock, id]
    );

    res.redirect('/admin'); // Redirige a la vista de administración después de editar
  } catch (error) {
    console.error('Error al actualizar el producto:', error);
    res.status(500).send('Error al actualizar el producto');
  }
});


app.post('/cart/remove/:id', authMiddleware, async (req, res) => {
  const productId = req.params.id;
  const userId = req.user.id;

  // Obtén la cantidad del producto que se está eliminando del carrito
  const cartItem = await sql('SELECT quantity FROM cart WHERE user_id = $1 AND product_id = $2', [userId, productId]);

  if (cartItem.length > 0) {
    const quantity = cartItem[0].quantity;

    // Elimina el producto del carrito
    await sql('DELETE FROM cart WHERE user_id = $1 AND product_id = $2', [userId, productId]);

    // Devuelve el stock del producto a su valor inicial
    await sql('UPDATE products SET stock = stock + $1 WHERE id = $2', [quantity, productId]);
  }

  res.redirect('/carrito');
});



app.post('/cart/add/:id', authMiddleware, async (req, res) => {
  const productId = req.params.id;
  const userId = req.user.id;

  // Verifica el stock del producto
  const product = await sql('SELECT stock FROM products WHERE id = $1', [productId]);
  
  if (product.length === 0 || product[0].stock <= 0) {
    return res.redirect('/catalog?error=out_of_stock'); // Redirige si no hay stock disponible
  }

  const existingItem = await sql('SELECT * FROM cart WHERE user_id = $1 AND product_id = $2', [userId, productId]);

  if (existingItem.length > 0) {
    // Si el producto ya está en el carrito, solo incrementa la cantidad
    await sql('UPDATE cart SET quantity = quantity + 1 WHERE user_id = $1 AND product_id = $2', [userId, productId]);
  } else {
    // Agrega el nuevo producto al carrito
    await sql('INSERT INTO cart (user_id, product_id, quantity) VALUES ($1, $2, $3)', [userId, productId, 1]);
  }

  // Actualiza el stock del producto
  await sql('UPDATE products SET stock = stock - 1 WHERE id = $1', [productId]);

  res.redirect('/catalog');
});



app.get('/catalog', async (req, res) => {
  const products = await sql('SELECT * FROM products');
  res.render('catalog', { products });
});


// Ruta para simular la actualización de la wallet
app.post('/admin/simulate-wallet', authMiddleware, async (req, res) => {
  if (!req.user.is_admin) {
      return res.status(403).send('No tienes permisos de administrador.');
  }

  const amount = parseFloat(req.body.amount);
  const userId = req.user.id;

  if (isNaN(amount) || amount <= 0) {
      return res.redirect('/admin?message=El monto debe ser un número positivo');
  }

  try {
      await sql('UPDATE users SET wallet = wallet + $1 WHERE id = $2', [amount, userId]);
      res.redirect('/admin?message=Billetera actualizada con éxito');
  } catch (error) {
      console.error('Error al actualizar la billetera:', error);
      res.redirect('/admin?message=Error al actualizar la billetera');
  }
});

//CREAR CLIENTE

// Ruta GET para renderizar el formulario de creación de cliente
app.get('/admin/clientes/crear', authMiddleware, (req, res) => {
  if (!req.user.is_admin) {
    return res.status(403).send('No tienes permisos de administrador.');
  }
  res.render('crear-cliente'); // Renderiza la vista `crear-cliente.handlebars`
});

// Ruta POST para manejar la creación de un cliente
app.post('/admin/clientes/crear', authMiddleware, async (req, res) => {
  if (!req.user.is_admin) {
    return res.status(403).send('No tienes permisos de administrador.');
  }

  const { rut_cliente, nombre, correo, saldo = 0, minutos_total = 0, minutos_disponibles = 0 } = req.body;

  try {
    const query = `
      INSERT INTO cliente (rut_cliente, nombre, correo, saldo, minutos_total, minutos_disponibles)
      VALUES ($1, $2, $3, $4, $5, $6)
    `;
    await sql(query, [rut_cliente, nombre, correo, saldo, minutos_total, minutos_disponibles]);
    res.redirect('/admin?message=Cliente creado con éxito.');
  } catch (error) {
    console.error('Error al añadir cliente:', error);
    res.status(500).send('Error al añadir cliente.');
  }
});

//editar
// Ruta GET para mostrar el formulario de edición de cliente
app.get('/admin/clientes/editar/:rut_cliente', authMiddleware, async (req, res) => {
  if (!req.user.is_admin) {
    return res.status(403).send('No tienes permisos de administrador.');
  }

  const { rut_cliente } = req.params;

  try {
    // Obtener los datos del cliente por su RUT
    const result = await sql('SELECT * FROM cliente WHERE rut_cliente = $1', [rut_cliente]);

    if (result.length === 0) {
      return res.status(404).send('Cliente no encontrado.');
    }

    // Renderizar la vista con los datos del cliente
    res.render('editar-cliente', { cliente: result[0] });
  } catch (error) {
    console.error('Error al obtener cliente:', error);
    res.status(500).send('Error al obtener cliente.');
  }
});

//eliminar 

// Ruta POST para eliminar un cliente
app.post('/admin/clientes/eliminar/:rut_cliente', authMiddleware, async (req, res) => {
  if (!req.user.is_admin) {
    return res.status(403).send('No tienes permisos de administrador.');
  }

  const { rut_cliente } = req.params;

  try {
    // Eliminar el cliente de la base de datos
    const query = 'DELETE FROM cliente WHERE rut_cliente = $1';
    await sql(query, [rut_cliente]);

    res.redirect('/admin?message=Cliente eliminado con éxito.');
  } catch (error) {
    console.error('Error al eliminar cliente:', error);
    res.status(500).send('Error al eliminar cliente.');
  }
});

app.get('/empleado-mas-faltas', authMiddleware, async (req, res) => {
  if (!req.user.is_admin) {
    return res.status(403).send('No tienes permisos de administrador.');
  }

  try {
    // Consulta para obtener el empleado con más días faltados por motivos externos
    const result = await sql(`
      SELECT 
          e.rut_empleado,
          e.nombre,
          COUNT(df.id_falta) AS total_faltas
      FROM 
          dias_faltados df
      JOIN 
          empleado e ON df.rut_empleado = e.rut_empleado
      WHERE 
          df.motivo IN ('Ausencia no justificada', 'Vacaciones') -- Ajustar si hay más motivos externos
      GROUP BY 
          e.rut_empleado, e.nombre
      ORDER BY 
          total_faltas DESC
      LIMIT 1;
    `);

    // Verificar si hay resultados
    const empleadoConMasFaltas = result.length > 0 ? result[0] : null;

    // Renderizar la vista con los datos obtenidos
    res.render('empleado-mas-faltas', { empleadoConMasFaltas });
  } catch (error) {
    console.error('Error al obtener el empleado con más faltas:', error);
    res.status(500).send('Error al obtener el empleado con más faltas.');
  }
});

app.get('/ingresos-trimestre', authMiddleware, async (req, res) => {
  try {
    // Consulta para calcular los ingresos totales en el trimestre actual
    const result = await sql(`
      SELECT 
          SUM(monto) AS ingresos_totales
      FROM 
          pago
      WHERE 
          fecha_pago >= DATE_TRUNC('quarter', CURRENT_DATE)
          AND fecha_pago < DATE_TRUNC('quarter', CURRENT_DATE) + INTERVAL '3 months';
    `);

    // Obtener el monto de ingresos totales
    const ingresosTotales = result[0].ingresos_totales || 0;

    // Renderizar la vista con los ingresos totales
    res.render('ingresos-trimestre', { ingresosTotales });
  } catch (error) {
    console.error('Error al calcular los ingresos totales del trimestre:', error);
    res.status(500).send('Error al calcular los ingresos totales del trimestre.');
  }
});

app.get('/mantenciones', authMiddleware, async (req, res) => {
  const { mes, anio } = req.query; // Recibir mes y año desde el formulario

  try {
    // Ejecutar la consulta SQL
    const result = await sql(`
      SELECT 
          hs.fecha,
          hs.codigo,
          e.descripcion AS componente,
          e.estado AS estado_componente,
          hs.minutos_total AS tiempo_utilizado
      FROM 
          historial_de_sesiones hs
      JOIN 
          equipo e ON hs.codigo = e.codigo
      WHERE 
          EXTRACT(MONTH FROM hs.fecha) = $1
          AND EXTRACT(YEAR FROM hs.fecha) = $2
          AND e.estado = 'En mantenimiento'
      ORDER BY 
          hs.fecha ASC;
    `, [mes, anio]);

    // Renderizar los resultados en Handlebars
    res.render('mantenciones', { mantenciones: result, mes, anio });
  } catch (error) {
    console.error('Error al obtener las mantenciones:', error);
    res.status(500).send('Error al obtener las mantenciones.');
  }
});



app.get('/costo-sesion', authMiddleware, async (req, res) => {
  const { rut_cliente, fecha } = req.query; // RUT y fecha enviados como parámetros en la URL

  try {
    // Consulta para calcular el costo total de la sesión
    const result = await sql(`
      SELECT 
          hs.fecha,
          hs.rut_cliente,
          hs.minutos_total,
          (hs.minutos_total * 10) AS costo_total -- Costo fijo por minuto ($10)
      FROM 
          historial_de_sesiones hs
      WHERE 
          hs.rut_cliente = $1
          AND hs.fecha = $2;
    `, [rut_cliente, fecha]);

    if (result.length === 0) {
      return res.render('costo-sesion', { error: 'No se encontró ninguna sesión con los parámetros proporcionados.' });
    }

    // Renderizar la vista con los datos obtenidos
    res.render('costo-sesion', { sesion: result[0], costo_por_minuto: 10 });
  } catch (error) {
    console.error('Error al calcular el costo de la sesión:', error);
    res.status(500).send('Error al calcular el costo de la sesión.');
  }
});











const PORT = process.env.PORT || 3003;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);
});
