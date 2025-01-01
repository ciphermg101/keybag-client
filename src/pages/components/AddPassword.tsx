import React, { useState } from 'react';

interface AddPasswordProps {
  newUrl: string;
  newUsername: string;
  newPassword: string;
  setNewUrl: (url: string) => void;
  setNewUsername: (username: string) => void;
  setNewPassword: (password: string) => void;
  addPassword: () => void;
  generatePassword: () => void;
}

const AddPassword: React.FC<AddPasswordProps> = ({ 
  newUrl, 
  newUsername, 
  newPassword, 
  setNewUrl, 
  setNewUsername, 
  setNewPassword, 
  addPassword, 
  generatePassword 
}) => {
  const [isPasswordVisible, setIsPasswordVisible] = useState(false);

  const handleGeneratePassword = () => {
    generatePassword();
    setIsPasswordVisible(true); // Make the password visible after generation
  };

  return (
    <div>
      <h2>Add Password</h2>
      <form onSubmit={(e) => { e.preventDefault(); addPassword(); }}>
        <div className="form-group">
          <input 
            type="url" 
            value={newUrl} 
            onChange={(e) => setNewUrl(e.target.value)} 
            placeholder="Enter site URL" 
            required 
          />
          <input 
            type="text" 
            value={newUsername} 
            onChange={(e) => setNewUsername(e.target.value)} 
            placeholder="Enter username" 
            required 
          />
          <div className="password-input-group">
            <input 
              type={isPasswordVisible ? "text" : "password"}
              value={newPassword} 
              onChange={(e) => setNewPassword(e.target.value)} 
              placeholder="Enter or generate password" 
              required 
            />
            <button 
              type="button" 
              className="generate-button" 
              onClick={handleGeneratePassword} 
              aria-label="Generate Password"
            >
              Generate Password
            </button>
          </div>
          <div className="button-container">
            <button className="add-button" type="submit">Add New Password</button>
          </div>
        </div>
      </form>
    </div>
  );
};

export default AddPassword;
