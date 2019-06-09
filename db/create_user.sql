INSERT INTO users1 (email, user_password)
VALUES ($1, $2)
RETURNING *;
