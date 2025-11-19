-- Create table for tracking tab/window switches during tests
CREATE TABLE IF NOT EXISTS tab_switches (
    switch_id INT AUTO_INCREMENT PRIMARY KEY,
    candidate_id INT NOT NULL,
    attempt_number INT NOT NULL,
    switch_type ENUM('switch_out', 'switch_back') NOT NULL,
    switched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (candidate_id) REFERENCES candidates(id) ON DELETE CASCADE,
    INDEX idx_candidate_attempt (candidate_id, attempt_number),
    INDEX idx_switched_at (switched_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

