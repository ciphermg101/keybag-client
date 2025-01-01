import React ,{ useState } from 'react';
import { useNavigate } from 'react-router-dom';
import './LandingPage.css'; 
import { Link } from 'react-router-dom';

const LandingPage: React.FC = () => {
    const navigate = useNavigate();
    const [menuOpen, setMenuOpen] = useState<boolean>(false);

    const handleSignUp = () => {
        navigate('/login'); 
    };

    const toggleMenu = () => {
        setMenuOpen(!menuOpen); 
    };

    const scrollToAuthors = (event: React.MouseEvent) => {
        event.preventDefault(); 
        const authorsSection = document.getElementById('authors-section');
        if (authorsSection) {
            authorsSection.scrollIntoView({ behavior: 'smooth' });
        }
        setMenuOpen(false);
    };

    return (
        <div className="landing-page">
            {/* Header Section */}
            <header className="landing-header">
            <img 
                    src="/src/assets/images/logo.png" 
                    alt="Logo" 
                    className="logo" 
                />

                <div className="hamburger-menu" onClick={toggleMenu}>
                    <div className={`bar ${menuOpen ? 'open' : ''}`}></div>
                    <div className={`bar ${menuOpen ? 'open' : ''}`}></div>
                    <div className={`bar ${menuOpen ? 'open' : ''}`}></div>
                </div>

                <h1>Welcome to Password Manager</h1>
            </header>

            {menuOpen && (
                <div className="menu">
                    <ul>
                    <li><Link to="/">Home</Link></li>
                    <li><Link to="/about">About</Link></li>
                    <li><a href="#" onClick={handleSignUp}>Sign Up</a></li>
                    <li><a href="#authors-section" onClick={scrollToAuthors}>Team</a></li>
                    </ul>
                </div>
            )}
            

               <section className="content-section">
                     <div className="text-section">
                    <div className="text-content">
                          <h2>Why Choose Our Password Manager?</h2>
                             <p>
                Our password manager offers top-notch security features, including 
                encrypted storage, password generation, and easy syncing across devices. 
                With our tool, you'll never forget a password again!
                                 <h2><b><i>Together We Can</i></b></h2>
                             </p>
                        </div>
                    </div>

             <div className="right-section">
                 <div className="image-section">
                     <img src="/src/assets/images/dash1.png" alt="Secure Passwords" className="mid-image" />
                    </div>
        
            <div className="cta-section">
                     <button onClick={handleSignUp} className="cta-button">Get Started</button>
                 </div>
             </div>
                </section>

                 {/* Authors Section */}
            <section id="authors-section" className="authors-section">
                <h2>Meet the Dev & Tech team</h2>
                <div className="authors-container">
                    <div className="author-card">
                        <img src="/src/assets/images/ath1.jpg" alt="Author 1" className="author-image" />
                        <h3>Silvia Munene</h3>
                        <p>Team Lead</p>
                    </div>
                    <div className="author-card">
                        <img src="/src/assets/images/author2.jpg" alt="Author 2" className="author-image" />
                        <h3>Wencylous Igadwa</h3>
                        <p>UI/UX Designer</p>
                    </div>
                    <div className="author-card">
                        <img src="/src/assets/images/author3.jpg" alt="Author 3" className="author-image" />
                        <h3>John Kilonzi</h3>
                        <p>Security Expert</p>
                    </div>
                    <div className="author-card">
                        <img src="/src/assets/images/ath4.jpg" alt="Author 4" className="author-image" />
                        <h3>Christopher Mbuthia</h3>
                        <p>Backend Dev</p>
                    </div>
                    <div className="author-card">
                        <img src="/src/assets/images/ath5.jpg" alt="Author 5" className="author-image" />
                        <h3>Emmanuel Kimathi</h3>
                        <p>Security Expert</p>
                    </div>
                    <div className="author-card">
                        <img src="/src/assets/images/author6.jpg" alt="Author 6" className="author-image" />
                        <h3>Dancun Karuku</h3>
                        <p>Security Expert</p>
                    </div>
                </div>
            </section>

            {/* Footer Section */}
            <footer className="landing-footer">
                <p>&copy; 2024 Password Manager. All rights reserved.</p>
            </footer>
        </div>
    );
};

export default LandingPage;

