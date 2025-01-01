// src/pages/AboutPage.tsx
import React from 'react';
import './AboutPage.css';

const AboutPage: React.FC = () => {
    return (
        <div className="about-page">
            <h1>About Us</h1>
            <section className="about-content">
                <h2>Description</h2>
                <p>
                    Welcome to our Password Manager, a secure and reliable solution designed to simplify 
                    password management. Our goal is to help you securely store, organize, and access your 
                    passwords anytime, anywhere.
                </p>

                <p>
                    We understand the importance of security and convenience, which is why our application comes with 
                    strong encryption, easy-to-use features, and seamless syncing across all your devices. 
                    With our Password Manager, you can focus on what matters without worrying about remembering 
                    complex passwords.
                </p>

                <h2>Our Mission</h2>
                <p>
                    Our mission is to provide a safe, accessible, and effective solution to manage your digital 
                    life. We are committed to maintaining high standards of privacy and security, so you can 
                    trust us with your data.
                </p>

                
            </section>
        </div>
    );
};

export default AboutPage;
