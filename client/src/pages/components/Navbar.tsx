import React from 'react';
import { useNavigate } from 'react-router-dom';
type NavbarProps = {
    menuOpen: boolean;
    handleMenuToggle: () => void;
    username: string;
    handleLogout: () => void;
    toggleTheme: () => void;
    isDarkMode: boolean;
};

const Navbar: React.FC<NavbarProps> = ({
    menuOpen,
    handleMenuToggle,
    handleLogout,
    toggleTheme,
    isDarkMode,
}) => {
    const [settingsOpen, setSettingsOpen] = React.useState(false);
    const navigate = useNavigate();
    const handleProfileClick = () => {
        navigate('/manage-profile');
    };
    const handleTwoFa = () => {
        navigate('/manage-two-fa');
    };

    const handleSettingsToggle = () => {
        setSettingsOpen(!settingsOpen);
    };

    return (
        <nav className="navbar">
            {/* Menu Button */}
            <div className="switch-theme-button" onClick={handleMenuToggle}>
                ☰
            </div>

            {/* Brand Name */}
            <div className="navbar-brand">Password Manager</div>

            {/* Links/Dropdown */}
            <div className="navbar-links">
                <div className="settings-dropdown">
                    <button 
                        className="dropdown-toggle settings-button" 
                        onClick={handleSettingsToggle} 
                        style={{
                            display: 'flex',
                            alignItems: 'center',
                            borderRadius: '5px',
                            padding: '10px 10px',
                            backgroundColor: '#0ED186FF',
                            border: 'none',
                            cursor: 'pointer'
                        }}
                    >
                        Settings
                    </button>
                    {settingsOpen && (
                        <div className="dropdown-content">
                            <button onClick={handleProfileClick}>Manage Profile</button>
                            <button onClick={handleTwoFa}>Manage Two-Factor Authentication</button>
                        </div>
                    )}
                </div>                                      
                <button onClick={handleLogout}>Logout</button>
            </div>

            {/* Dropdown Menu */}
            {menuOpen && (
                <div className="dropdown-menu">
                    <button onClick={toggleTheme}>
                        {isDarkMode ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
                    </button>
                </div>
            )}
        </nav>
    );
};

export default Navbar;
