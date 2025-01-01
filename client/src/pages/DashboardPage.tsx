import React, { useState, useEffect, useCallback } from 'react';
import './Dashboard.css';
import { useNavigate } from 'react-router-dom';
import { Dialog, DialogActions, DialogContent, DialogTitle, Button } from '@mui/material';
import axiosInstance from "../utils/axiosInstance";
import { getAuthToken, getCsrfToken } from "../utils/axiosInstance";
import Navbar from './components/Navbar';
import Sidebar from './components/Sidebar';
import AddPassword from './components/AddPassword';
import RecentActivities from './components/RecentActivities';
import AvailablePasswords from './components/AvailablePasswords';
import PasswordStrengthTable from './components/PasswordStrengthTable';
import PasswordsAnalysisReport from './components/PasswordAnalysis';
import axios from 'axios';

// Define the props interface
interface Props {
    username: string;
    onLogout: () => void;
}

interface PasswordEntry {
    url: string;
    username: string;
    password: string;
}

interface PasswordAnalyzeEntry {
    url: string;
    username: string;
    password: string;
    score: number;          
    strengthText: string;   
    suggestions: string[];
}

type SelectedContent = 'addPassword' | 'recentActivities' | 'availablePasswords' | 'analysisReport' | null;


interface VisiblePasswords {
    [index: number]: boolean;
}

const Dashboard: React.FC<Props> = ({ username, onLogout }) => {
    const navigate = useNavigate();
    const [passwords, setPasswords] = useState<PasswordEntry[]>([]);
    const [recentActivities, setRecentActivities] = useState<{ activity: string, timestamp: string }[]>([]);
    const [newUrl, setNewUrl] = useState<string>('');
    const [newUsername, setNewUsername] = useState<string>('');
    const [newPassword, setNewPassword] = useState<string>('');
    const [selectedContent, setSelectedContent] = useState<SelectedContent>(null);
    const [editIndex, setEditIndex] = useState<number | null>(null);
    const [editedEntry, setEditedEntry] = useState<PasswordEntry | null>(null);
    const [isDarkMode, setIsDarkMode] = useState(false);
    const [visiblePasswords, setVisiblePasswords] = useState<VisiblePasswords>({});
    const [importing, setImporting] = useState(false);
    const [, setError] = useState<string | null>(null);
    const [menuOpen, setMenuOpen] = useState(false);
    const [passwordStrength, setPasswordStrength] = useState<PasswordAnalyzeEntry[]>([]);
    const [fetchedUsername, setFetchedUsername] = useState<string>(username);
    const [openDialog, setOpenDialog] = useState(false);
    
    // Password strength analyzer function
    const analyzePasswordStrength = (password: string) => {
        let score = 0;
        let text = 'Weak';
    
        if (password.length >= 8) score++;
        if (/[A-Z]/.test(password)) score++;
        if (/[a-z]/.test(password)) score++;
        if (/[0-9]/.test(password)) score++;
        if (/[^A-Za-z0-9]/.test(password)) score++;
    
        switch (score) {
            case 1:
            case 2:
                text = 'Weak';
                break;
            case 3:
                text = 'Moderate';
                break;
            case 4:
                text = 'Strong';
                break;
            case 5:
                text = 'Very Strong';
                break;
        }
    
        // Update the state with an object that conforms to PasswordStrengthEntry[]
        setPasswordStrength((prevState) => [
            ...prevState,
            {
                url: '',
                username: '',
                password: password,
                score: score,
                strengthText: text,
                suggestions: [] // Add any suggestion logic here if necessary
            }
        ]);
        return { score, text };
    };       

    // Fetch all credentials data
    useEffect(() => {
        const fetchCredentials = async () => {
            try {
                const response = await axiosInstance.get('/account/fetch-allcreds', { withCredentials: true });
                if (response.status === 200) {
                    setPasswords(response.data);
                }
            } catch (error) {
                console.error('Error fetching credentials:', error);
                setError('Failed to load credentials. Please try again.');
            }
        };

        fetchCredentials();
    }, []); // Empty dependency array ensures this runs only once

    // Check password strength
    useEffect(() => {
        const checkPasswordStrength = () => {
            const evaluatedPasswords = passwords.map((entry) => {
                const strength = analyzePasswordStrength(entry.password);
                return {
                    ...entry,
                    score: strength.score,
                    strengthText: strength.text,
                    suggestions: [], // Add suggestions logic here
                };
            });
            setPasswordStrength(evaluatedPasswords); // Save the evaluated passwords in state
        };

        if (passwords.length > 0) {
            checkPasswordStrength();
        }
    }, [passwords]); // Runs whenever passwords are updated

    // Fetch the username from the backend
    useEffect(() => {
        const fetchUsername = async () => {
            try {
                const response = await axiosInstance.get('/account/get-username', { withCredentials: true });
                if (response.status === 200) {
                    setFetchedUsername(response.data.username);
                }
            } catch (error) {
                console.error('Error fetching username:', error);
            }
        };

        fetchUsername();
    }, []); // Empty dependency array ensures this runs only once

    const handleLogout = async () => {
        try {
            await axiosInstance.post('/auth/logout');
            localStorage.removeItem('authToken');
            sessionStorage.removeItem('authToken');
            localStorage.removeItem('csrfToken');
            document.cookie = 'csrfToken=; Max-Age=0; path=/;';
            if (typeof onLogout === 'function') {
                onLogout();
            }
            setOpenDialog(true); // Open dialog after successful logout
            setTimeout(() => {
                navigate('/login');
            }, 3000);
        } catch (error) {
            console.error('Error during logout:', error);
            setError('Logout failed. Please try again.');
        }
    };
    const addPassword = async () => {
        if (newUrl && newUsername && newPassword) {
            try {
                try {
                    new URL(newUrl);
                } catch {
                    alert('Please enter a valid URL.');
                    return;
                }
    
                const payload = {
                    site_url: newUrl,
                    username: newUsername,
                    password: newPassword,
                };
    
                const response = await axiosInstance.post("/account/save-password", payload, { withCredentials: true });
    
                if (response.status === 201) {
                    // Assuming the response contains the newly created password
                    const newEntry = { 
                        url: newUrl, 
                        username: newUsername, 
                        password: newPassword 
                    };
    
                    setPasswords([...passwords, newEntry]);
    
                    const timestamp = new Date().toLocaleString();
                    setRecentActivities([
                        ...recentActivities,
                        { activity: `Added password for ${newUsername} at ${newUrl}`, timestamp }
                    ]);
    
                    // Reset the form fields
                    setNewUrl('');
                    setNewUsername('');
                    setNewPassword('');
    
                    alert("Password added successfully!");
                } else {
                    alert("Failed to add password. Please try again.");
                }
            } catch {
                alert('An error occurred. Please try again.');
            }
        } else {
            alert('Please fill in all fields.');
        }
    };    

    const deletePassword = async (index: number) => {
        try {
            const passwordToDelete = passwords[index];
    
            // Show confirmation prompt before deletion
            const isConfirmed = window.confirm(`Are you sure you want to delete the password for ${passwordToDelete.username} at ${passwordToDelete.url}?`);
    
            if (!isConfirmed) return; // If not confirmed, do nothing
    
            // First, delete the password from the database (we no longer need to check for id)
            await deletePasswordFromDatabase(passwordToDelete);
    
            // Then, remove it from the local state
            const updatedPasswords = passwords.filter((_, i) => i !== index);
            setPasswords(updatedPasswords);
    
            // Log the activity
            const timestamp = new Date().toLocaleString();
            setRecentActivities([
                ...recentActivities,
                { activity: `Deleted password for ${passwordToDelete.username} at ${passwordToDelete.url}`, timestamp },
            ]);
        } catch (error) {
            // Handle any errors that occur during the deletion
            console.error('Failed to delete password:', error);
            setError('Failed to delete password. Please try again.');
        }
    };
    
    const deletePasswordFromDatabase = async (passwordEntry: PasswordEntry) => {
        try {
            await axiosInstance.delete('/account/delete-password', {
                withCredentials: true,
                data: { username: passwordEntry.username, site_url: passwordEntry.url }, // Send the request payload
              });              
        } catch (error) {
            console.error('Failed to delete password:', error);
            setError('Failed to delete password. Please try again.');
        }
    };    
    
    const handleEdit = (index: number) => {
        setEditIndex(index);
        setEditedEntry(passwords[index]);
    };

    const handleEditedFieldChange = (field: 'url' | 'username' | 'password', value: string) => {
        if (editedEntry) {
            setEditedEntry({ ...editedEntry, [field]: value });
        }
    };

    const saveEdit = async () => {
        if (editIndex !== null && editedEntry) {
            const updatedPasswords = [...passwords];
            updatedPasswords[editIndex] = editedEntry;
            setPasswords(updatedPasswords);
            setEditIndex(null);
            setEditedEntry(null);
            try {
                await updatePasswordInDatabase(editedEntry);
            } catch {
                setError('Failed to save changes. Please try again.');
            }
        }
    };    

    const cancelEdit = () => {
        setEditIndex(null);
        setEditedEntry(null);
    };

    const updatePasswordInDatabase = async (passwordEntry: PasswordEntry) => {
        try {
            await axiosInstance.post('/account/update-password', passwordEntry, { withCredentials: true });
        } catch (error) {
            console.error('Failed to update password:', error);
            setError('Failed to update password. Please try again.');
        }
    };
    
    // Function to generate a random password
    const generatePassword = () => {
        const length = 12;
        const uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const lowercase = "abcdefghijklmnopqrstuvwxyz";
        const numbers = "0123456789";
        const specialChars = "!@#$%^&*()_+[]{}|;:,.<>?";
        
        const allChars = uppercase + lowercase + numbers + specialChars;
    
        // Ensure the password contains at least one of each required character type
        let password = [
            uppercase[Math.floor(Math.random() * uppercase.length)],
            lowercase[Math.floor(Math.random() * lowercase.length)],
            numbers[Math.floor(Math.random() * numbers.length)],
            specialChars[Math.floor(Math.random() * specialChars.length)]
        ];
    
        // Fill the rest of the password length with random characters from allChars
        for (let i = password.length; i < length; i++) {
            password.push(allChars[Math.floor(Math.random() * allChars.length)]);
        }
    
        // Shuffle the password array to ensure randomness
        password = password.sort(() => Math.random() - 0.5);
    
        // Set the new password in the state
        setNewPassword(password.join(''));
    };

    const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
        const file = event.target.files?.[0];
        if (file) {
            const formData = new FormData();
            formData.append('csvFile', file);
    
            setImporting(true);
            setError(null);
    
            try {
                const csrfToken = await getCsrfToken();
                const authToken = getAuthToken();
    
                const response = await axiosInstance.post('/account/import-passwords', formData, {
                    headers: {
                        'Content-Type': 'multipart/form-data',
                        'X-CSRF-Token': csrfToken,
                        'Authorization': `Bearer ${authToken}`,
                    }, withCredentials: true,
                });
    
                if (response.status === 200) {
                    alert('Passwords imported successfully!');
                }else if (response.status === 201) {
                    alert('Passwords imported successfully! but duplicate records have been skipped!');
                } 
            } catch (err) {
                console.error('Error importing passwords:', err);
    
                // Handle Axios error
                if (axios.isAxiosError(err)) {
                    if (err.response) {
                        // Server responded with a status other than 2xx
                        const responseMessage = err.response.data.message || 'An error occurred while importing the passwords.';
                        
                        // Check if the error is related to file type
                        if (responseMessage.includes('Only CSV files are allowed')) {
                            alert('Please check the file type. Only CSV files are accepted.');
                        } else {
                            setError(responseMessage);
                        }
                    } else if (err.request) {
                        // No response from the server
                        setError('No response from the server. Please try again later.');
                    } else {
                        // Something else went wrong
                        setError('An error occurred while processing the request.');
                    }
                } else {
                    setError('An unexpected error occurred.');
                }
            } finally {
                setImporting(false);
            }
        }
    };

    const exportPasswordsToCSV = async () => {
        try {
            // Fetch the CSRF token and auth token
            const csrfToken = await getCsrfToken();
            const authToken = getAuthToken();
    
            // Send GET request to export passwords
            const response = await axiosInstance.get('/account/export-passwords', {
                headers: {
                    'X-CSRF-Token': csrfToken,
                    'Authorization': `Bearer ${authToken}`,
                }, withCredentials: true,
            });
            
            // If the response is not successful, display an error
            if (response.status !== 200) {
                console.error('Failed to fetch passwords for export');
                setError('Failed to fetch passwords for export.');
                return;
            }
    
            // Assuming the backend sends a CSV file directly (blob)
            const blob = new Blob([response.data], { type: 'text/csv;charset=utf-8;' });
            const url = URL.createObjectURL(blob);
    
            // Trigger the download by creating a temporary link
            const link = document.createElement('a');
            link.href = url;
            link.download = 'passwords_export.csv';
            link.click();
    
            // Clean up the object URL
            URL.revokeObjectURL(url);
    
            // Log the successful export activity
            setRecentActivities([
                ...recentActivities,
                { activity: 'Exported passwords to CSV', timestamp: new Date().toLocaleString() },
            ]);
        } catch (error) {
            console.error('Error exporting passwords:', error);
            setError('Failed to export passwords. Please try again.');
        }
    };              

    const copyCredentialsToClipboard = (index: number) => {
        const password = passwords[index];
        const textToCopy = `Username: ${password.username}\nPassword: ${password.password}`;
        navigator.clipboard.writeText(textToCopy)
            .then(() => alert("Username and Password copied to clipboard!"))
            .catch((err) => console.error("Failed to copy text: ", err));
    };

    const togglePasswordVisibility = (index: number) => {
        setVisiblePasswords((prev) => ({
            ...prev,
            [index]: !prev[index],
        }));
    };


     // Dark/Light mode
     const toggleTheme = () => {
        setIsDarkMode(!isDarkMode);
        document.body.classList.toggle('dark-mode', !isDarkMode);
    };

    const handleContentSelect = (content: SelectedContent) => {
        setSelectedContent(content);
    };

    const handleMenuToggle = () => {
        setMenuOpen(!menuOpen);
    };

    const handleCloseDialog = useCallback(() => {
        setOpenDialog(false);
    }, []);    

    return (
        <div className={`dashboard ${isDarkMode ? 'dark' : 'light'}`}>
            <Navbar 
                username={username} 
                handleLogout={handleLogout} 
                toggleTheme={toggleTheme} 
                menuOpen={menuOpen} 
                handleMenuToggle={handleMenuToggle} 
                isDarkMode={isDarkMode} 
            />
            <h1>Welcome, {fetchedUsername}</h1>
    
            {/* Main Container */}
            <div className="container">
                <Sidebar handleContentSelect={handleContentSelect} />
                <div className="content">
                    {/* Default content showing PasswordStrengthTable */}
                    {selectedContent === null && (
                        <>
                            <h2>Your Passwords</h2>
                            <PasswordStrengthTable password={passwordStrength} />
                        </>
                    )}
                    
                    {selectedContent === 'availablePasswords' && (
                        <AvailablePasswords
                            passwords={passwords}
                            visiblePasswords={visiblePasswords}
                            togglePasswordVisibility={togglePasswordVisibility}
                            editIndex={editIndex}
                            editedEntry={editedEntry}
                            handleEditedFieldChange={handleEditedFieldChange}
                            saveEdit={saveEdit}
                            cancelEdit={cancelEdit}
                            copyCredentialsToClipboard={copyCredentialsToClipboard}
                            handleEdit={handleEdit}
                            deletePassword={deletePassword}
                            importing={importing}
                            exportPasswordsToCSV={exportPasswordsToCSV}
                            handleFileUpload={handleFileUpload}

                        />
                    )}
                    {selectedContent === 'addPassword' && (
                        <AddPassword
                            newUrl={newUrl}
                            newUsername={newUsername}
                            newPassword={newPassword}
                            setNewUrl={setNewUrl} // Function to update the URL
                            setNewUsername={setNewUsername} // Function to update the username
                            setNewPassword={setNewPassword} // Function to update the password
                            addPassword={addPassword} // Function to handle password addition
                            generatePassword={generatePassword} // Function to generate a random password
                        />
                    )}
                    {selectedContent === 'recentActivities' && (
                        <RecentActivities
                            recentActivities={recentActivities.map((activityObj) => {
                                // Format the activity string as required
                                const { activity, timestamp } = activityObj;
                                return `${activity} (${timestamp})`;
                            })}
                        />
                    )}
                    {selectedContent === 'analysisReport' && (
                        <PasswordsAnalysisReport 
                            passwordStrength={passwordStrength} 
                        />
                    )}
                </div>
            </div>
            <Dialog open={openDialog} onClose={handleCloseDialog}>
                <DialogTitle>Logout Successful</DialogTitle>
                <DialogContent>
                    <p>You have logged out successfully!</p>
                </DialogContent>
                <DialogActions>
                    <Button onClick={handleCloseDialog} color="primary">Close</Button>
                </DialogActions>
            </Dialog>
        </div>
    );
    };
    
    export default Dashboard;
    
