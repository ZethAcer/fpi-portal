// ==========================================
// EMPLOYEE borrowing_logs
// ==========================================
app.get('/api/employees/lookup/:employeeId', async (req, res) => {
  const { employeeId } = req.params;
  try {
    const query = `
      SELECT employee_firstname, employee_middlename, employee_lastname, department
      FROM borrowing_logs
      WHERE employee_id = $1
      LIMIT 1;
    `;
    const result = await pool.query(query, [employeeId]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Employee not found in borrowing logs' });
    }
    res.json({ success: true, data: result.rows[0] });
  } catch (err) {
    console.error('Error looking up employee:', err.message);
    res.status(500).json({ success: false, message: 'Server database error' });
  }
});



// 1. GET ALL BORROWING RECORDS
app.get('/api/borrowing_logs', async (req, res) => {
  try {
    const query = `
      SELECT id, date_borrowed, employee_id, employee_firstname, employee_middlename, employee_lastname,
             department, item_code, equipment_category, purpose, date_returned, return_condition, received_by, status
      FROM borrowing_logs
      ORDER BY id DESC;
    `;
    const result = await pool.query(query);
    res.json({ success: true, data: result.rows });
  } catch (err) {
    console.error('Error fetching borrowing logs:', err.message);
    res.status(500).json({ success: false, message: 'Server database error' });
  }
});

// 2. AUTOFILL CATEGORY BY ITEM CODE LOOKUP
app.get('/api/hardware_assets/category/:itemCode', async (req, res) => {
  const { itemCode } = req.params;
  try {
    const result = await pool.query('SELECT category FROM hardware_assets WHERE item_code ILIKE $1', [itemCode]);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Item code not found' });
    }
    res.json({ success: true, category: result.rows[0].category });
  } catch (err) {
    console.error('Error fetching category:', err.message);
    res.status(500).json({ success: false, message: 'Server database error' });
  }
});

// 3. CREATE NEW BORROWING RECORD
app.post('/api/borrowing_logs', async (req, res) => {
  const {
    date_borrowed, employee_id, employee_firstname, employee_middlename, employee_lastname,
    department, item_code, equipment_category, purpose, received_by
  } = req.body;

  try {
    const query = `
      INSERT INTO borrowing_logs 
        (date_borrowed, employee_id, employee_firstname, employee_middlename, employee_lastname, department, item_code, equipment_category, purpose, received_by, status)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'Borrowed')
      RETURNING *;
    `;
    const values = [
      date_borrowed, employee_id, employee_firstname, employee_middlename, employee_lastname,
      department, item_code, equipment_category, purpose, received_by
    ];

    const result = await pool.query(query, values);
    
    // Optional: update hardware status to 'Borrowed'
    await pool.query("UPDATE hardware_assets SET status = 'Borrowed' WHERE item_code ILIKE $1", [item_code]);

    res.json({ success: true, data: result.rows[0] });
  } catch (err) {
    console.error('Error logging borrow record:', err.message);
    res.status(500).json({ success: false, message: 'Server database error' });
  }
});

// 4. PROCESS ITEM RETURN
app.put('/api/borrowing_logs/return/:id', async (req, res) => {
  const { id } = req.params;
  const { date_returned, return_condition, received_by, item_code } = req.body;

  try {
    const query = `
      UPDATE borrowing_logs
      SET date_returned = $1, return_condition = $2, received_by = $3, status = 'Returned'
      WHERE id = $4
      RETURNING *;
    `;
    const result = await pool.query(query, [date_returned, return_condition, received_by, id]);

    // Restore hardware asset status back to 'Operational'
    if (item_code) {
      await pool.query("UPDATE hardware_assets SET status = 'Operational' WHERE item_code ILIKE $1", [item_code]);
    }

    res.json({ success: true, data: result.rows[0] });
  } catch (err) {
    console.error('Error updating return record:', err.message);
    res.status(500).json({ success: false, message: 'Server database error' });
  }
});