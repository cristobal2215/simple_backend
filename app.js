const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
app.use(bodyParser.json());
app.use(cors());

// Configura la conexión con la base de datos MySQL
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '1234',
  database: 'veterinaria',
});

connection.connect((err) => {
  if (err) {
    console.error('Error al conectar a la base de datos:', err);
    return;
  }
  console.log('Conexión exitosa a la base de datos.');
});

const secretKey = 'tu_secreto'; // Cambia esto por una clave secreta fuerte y segura

// Middleware para verificar el token JWT en rutas protegidas
const authenticateToken = (req, res, next) => {
  const token = req.header('Authorization');

  if (!token) {
    res.status(401).json({ message: 'Acceso no autorizado' });
    return;
  }

  jwt.verify(token, secretKey, (err, payload) => {
    if (err) {
      res.status(403).json({ message: 'Acceso no autorizado' });
    } else {
      // Agregar el payload decodificado a la solicitud para que pueda ser utilizado en las rutas protegidas
      req.user = payload;
      next();
    }
  });
};

// Ruta de prueba para verificar que el servidor funciona correctamente
app.get('/', (req, res) => {
  res.send('¡Backend funcionando correctamente!');
});

app.post('/registro', (req, res) => {
  const { nombre, email, contraseña, rol } = req.body;

  // Verificar si el email ya está registrado
  const checkEmailSql = 'SELECT * FROM usuarios WHERE email = ?';
  connection.query(checkEmailSql, [email], (err, result) => {
    if (err) {
      console.error('Error al verificar email:', err);
      res.status(500).json({ message: 'Error al verificar email' });
    } else {
      if (result.length > 0) {
        // El email ya está registrado
        res.status(409).json({ message: 'El email ya está registrado' });
      } else {
        // Hash de la contraseña
        bcrypt.hash(contraseña, 10, (err, hash) => {
          if (err) {
            console.error('Error al encriptar contraseña:', err);
            res.status(500).json({ message: 'Error al registrar usuario' });
          } else {
            // Contraseña hasheada
            const hashedContraseña = hash;

            // Proceder con la inserción del nuevo usuario en la base de datos
            const sql = 'INSERT INTO usuarios (nombre, email, contraseña, rol) VALUES (?, ?, ?, ?)';
            const values = [nombre, email, hashedContraseña, rol];

            connection.query(sql, values, (err, result) => {
              if (err) {
                console.error('Error al registrar usuario:', err);
                res.status(500).json({ message: 'Error al registrar usuario' });
              } else {
                console.log('Usuario registrado con éxito.');
                res.status(200).json({ message: 'Usuario registrado con éxito' });
              }
            });
          }
        });
      }
    }
  });
});

app.post('/login', (req, res) => {
  const { email, contraseña } = req.body;

  // Verificar si el email existe en la base de datos
  const checkEmailSql = 'SELECT * FROM usuarios WHERE email = ?';
  connection.query(checkEmailSql, [email], (err, result) => {
    if (err) {
      console.error('Error al verificar email:', err);
      res.status(500).json({ message: 'Error al verificar email' });
    } else {
      if (result.length === 0) {
        // El email no existe en la base de datos
        res.status(401).json({ message: 'Credenciales inválidas' });
      } else {
        // Verificar la contraseña hasheada
        bcrypt.compare(contraseña, result[0].contraseña, (err, isMatch) => {
          if (err) {
            console.error('Error al comparar contraseñas:', err);
            res.status(500).json({ message: 'Error al verificar credenciales' });
          } else {
            if (isMatch) {
              // Contraseña válida, generar token JWT
              const payload = { id: result[0].id, email: result[0].email, rol: result[0].rol };
              jwt.sign(payload, secretKey, { expiresIn: '1h' }, (err, token) => {
                if (err) {
                  console.error('Error al generar token JWT:', err);
                  res.status(500).json({ message: 'Error al iniciar sesión' });
                } else {
                  // Enviar el token JWT al cliente
                  res.status(200).json({ token });
                }
              });
            } else {
              // Contraseña inválida
              res.status(401).json({ message: 'Credenciales inválidas' });
            }
          }
        });
      }
    }
  });
});

app.get('/perfil', authenticateToken, (req, res) => {
  const { id, email, rol } = req.user;

  if (rol === 'cliente') {
    const getMascotasSql = 'SELECT * FROM mascotas WHERE cliente_id = ?';
    const getCitasSql = 'SELECT * FROM citas WHERE cliente_id = ?';

    connection.query(getMascotasSql, [id], (err, mascotas) => {
      if (err) {
        console.error('Error al obtener mascotas:', err);
        res.status(500).json({ message: 'Error al obtener mascotas' });
      } else {
        connection.query(getCitasSql, [id], (err, citas) => {
          if (err) {
            console.error('Error al obtener citas:', err);
            res.status(500).json({ message: 'Error al obtener citas' });
          } else {
            res.status(200).json({ id, email, rol, mascotas, citas });
          }
        });
      }
    });
  } else if (rol === 'veterinario') {
    const getPacientesSql = 'SELECT * FROM mascotas WHERE veterinario_id = ?';

    connection.query(getPacientesSql, [id], (err, pacientes) => {
      if (err) {
        console.error('Error al obtener pacientes:', err);
        res.status(500).json({ message: 'Error al obtener pacientes' });
      } else {
        res.status(200).json({ id, email, rol, pacientes });
      }
    });
  } else if (rol === 'administrador') {
    const getInventarioSql = 'SELECT * FROM inventario_productos';

    connection.query(getInventarioSql, (err, inventario) => {
      if (err) {
        console.error('Error al obtener inventario:', err);
        res.status(500).json({ message: 'Error al obtener inventario' });
      } else {
        res.status(200).json({ id, email, rol, inventario });
      }
    });
  } else {
    res.status(400).json({ message: 'Rol de usuario no válido' });
  }
});

// Ruta y controlador para agendar citas
app.post('/agendar-cita', authenticateToken, (req, res) => {
  const { fecha_hora, descripcion, veterinario_id } = req.body;
  const cliente_id = req.user.id; // Obtenemos el ID del usuario autenticado (cliente)

  // Aquí debes validar los datos de la cita, como asegurarte de que la fecha y hora sean válidas,
  // y que el veterinario con el ID especificado exista en la base de datos.

  const sql = 'INSERT INTO citas (fecha_hora, cliente_id, veterinario_id, descripcion) VALUES (?, ?, ?, ?)';
  const values = [fecha_hora, cliente_id, veterinario_id, descripcion];

  connection.query(sql, values, (err, result) => {
    if (err) {
      console.error('Error al agendar cita:', err);
      res.status(500).json({ message: 'Error al agendar cita' });
    } else {
      console.log('Cita agendada con éxito.');
      res.status(200).json({ message: 'Cita agendada con éxito' });
    }
  });
});

// Inicia el servidor en el puerto 5000 (o el que desees)
const port = 5000;
app.listen(port, () => {
  console.log(`Servidor backend iniciado en http://localhost:${port}`);
});
