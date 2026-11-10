<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Resumen de Productos - Banco Central</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #e9ecef; margin: 0; padding: 20px; }
        .dashboard { background: white; padding: 30px; border-radius: 10px; box-shadow: 0px 4px 15px rgba(0,0,0,0.1); max-width: 600px; margin: 40px auto; }
        .header { border-bottom: 2px solid #004085; padding-bottom: 10px; margin-bottom: 20px; }
        h2 { color: #004085; margin: 0; }
        .balance-box { background: #d4edda; color: #155724; padding: 20px; border-radius: 8px; text-align: center; margin-bottom: 20px; border: 1px solid #c3e6cb; }
        .saldo { font-size: 32px; font-weight: bold; margin: 10px 0; }
        .btn-salir { background-color: #dc3545; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; float: right; font-weight: bold; }
        .btn-salir:hover { background-color: #c82333; }
        ul { list-style-type: none; padding: 0; }
        li { padding: 10px; border-bottom: 1px solid #ddd; }
    </style>
</head>
<body>
    <div class="dashboard">
        <div class="header">
            <button class="btn-salir" onclick="window.location.href='/index.html'">Cerrar Sesión</button>
            <h2>🏦 Banco Central</h2>
        </div>

        <h3>Resumen de tu Cuenta Ahorros</h3>
        <div class="balance-box">
            <p style="margin: 0;">Saldo Disponible</p>
            <div class="saldo">$ 1,450,200.00</div>
        </div>

        <h3>Últimos Movimientos</h3>
        <ul>
            <li>🟢 Transferencia recibida - <b>$ 500,000.00</b></li>
            <li>🔴 Pago factura de energía - <b>$ 120,000.00</b></li>
            <li>🔴 Retiro en cajero automático - <b>$ 200,000.00</b></li>
        </ul>
    </div>
</body>
</html>