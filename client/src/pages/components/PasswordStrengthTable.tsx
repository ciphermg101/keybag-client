import React, { useState } from 'react';

type PasswordAnalyzeEntry = {
    url: string;
    username: string;
    password: string;
    score: number;
    strengthText: string;
    suggestions: string[];
};

type PasswordStrengthTableProps = {
    password: PasswordAnalyzeEntry[];
};

const PasswordStrengthTable: React.FC<PasswordStrengthTableProps> = ({ password }) => {
    const [sortOption, setSortOption] = useState<'score' | 'alphabetical'>('score');
    const [searchQuery, setSearchQuery] = useState<string>('');

    const getStrengthClass = (score: number): string => {
        switch (score) {
            case 1:
                return 'strength-weak';
            case 2:
                return 'strength-weak';
            case 3:
                return 'strength-moderate';
            case 4:
                return 'strength-strong';
            case 5:
                return 'strength-very-strong';
            default:
                return '';
        }
    };

    const generateComments = (score: number): string[] => {
        switch (score) {
            case 1:
                return ["Password is very weak. Consider adding more characters"];
            case 2:
                return [
                    "Password is weak. Consider adding a mix of uppercase and lowercase letters.",
                    "Include numbers and special characters to increase strength."
                ];
            case 3:
                return [
                    "Password is moderate. Adding more special characters can improve security.",
                    "Consider making the password longer for better protection."
                ];
            case 4:
                return [
                    "Password is strong, but try adding a symbol for enhanced security.",
                    "Consider using a longer password for increased security."
                ];
            case 5:
                return ["Very strong password! Excellent work."];
            default:
                return [];
        }
    };

    const removeProtocol = (url: string): string => {
        return url.replace(/^https?:\/\//, '');
    };

    const sortedPasswords = [...password].sort((a, b) => {
        if (sortOption === 'score') {
            return a.score - b.score;
        } else {
            const strippedUrlA = removeProtocol(a.url);
            const strippedUrlB = removeProtocol(b.url);
            return strippedUrlA.localeCompare(strippedUrlB);
        }
    });

    const filteredPasswords = sortedPasswords.filter((entry) =>
        removeProtocol(entry.url).toLowerCase().includes(searchQuery.toLowerCase())
    );

    const groupedByScore: Record<number, PasswordAnalyzeEntry[]> = filteredPasswords.reduce((acc, entry) => {
        if (!acc[entry.score]) {
            acc[entry.score] = [];
        }
        acc[entry.score].push(entry);
        return acc;
    }, {} as Record<number, PasswordAnalyzeEntry[]>);

    if (sortOption === 'alphabetical') {
        Object.keys(groupedByScore).forEach((score) => {
            groupedByScore[parseInt(score, 10)] = groupedByScore[parseInt(score, 10)].sort((a, b) => {
                const strippedUrlA = removeProtocol(a.url);
                const strippedUrlB = removeProtocol(b.url);
                return strippedUrlA.localeCompare(strippedUrlB);
            });
        });
    }

    return (
        <div className="password-strength">
            <div className="header-options">
                <div className="sort-options">
                    <label htmlFor="sort-select">Sort by:</label>
                    <select
                        id="sort-select"
                        value={sortOption}
                        onChange={(e) => setSortOption(e.target.value as 'score' | 'alphabetical')}
                    >
                        <option value="score">Score</option>
                        <option value="alphabetical">Alphabetically</option>
                    </select>
                </div>

                {/* Search Bar */}
                <div className="search-bar">
                    <label htmlFor="search-input">Search by site:</label>
                    <input
                        id="search-input"
                        type="text"
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        placeholder="Search by site URL"
                    />
                </div>
            </div>

            <table className="password-strength-table">
                <thead>
                    <tr>
                        <th style={{ width: '30%' }}>Site</th>
                        <th>Password</th>
                        <th>Strength</th>
                        <th>Comments</th>
                    </tr>
                </thead>
                <tbody>
                    {Object.entries(groupedByScore).map(([score, entries]) => {
                        const scoreNum = parseInt(score, 10);
                        const comments = generateComments(scoreNum);

                        return (
                            <React.Fragment key={score}>
                                {entries.map((entry, index) => (
                                    <tr key={`${entry.url}-${index}`}>
                                        <td className="site-url-cell">{entry.url}</td>
                                        <td>{'•'.repeat(entry.password.length)}</td>
                                        <td>
                                            <div className="strength-bar">
                                                <div
                                                    className={`strength-level ${getStrengthClass(entry.score)}`}
                                                    style={{ width: `${(entry.score / 4.5) * 100}%` }}
                                                ></div>
                                            </div>
                                            <p>{entry.strengthText}</p>
                                        </td>
                                        {index === 0 && (
                                            <td rowSpan={entries.length}>
                                                <ul>
                                                    {comments.map((tip, i) => (
                                                        <li key={i}>{tip}</li>
                                                    ))}
                                                </ul>
                                            </td>
                                        )}
                                    </tr>
                                ))}
                            </React.Fragment>
                        );
                    })}
                </tbody>
            </table>
        </div>
    );
};

export default PasswordStrengthTable;
