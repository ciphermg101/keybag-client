import { jsPDF } from "jspdf";
import "jspdf-autotable";
import Chart from "chart.js/auto";
import ChartDataLabels from "chartjs-plugin-datalabels";
import { useEffect, useRef } from "react";

// Define the entry type for each password with a score and strength
type PasswordAnalyzeEntry = {
    url: string;
    username: string;
    password: string;
    score: number;
    strengthText: string;
    suggestions: string[];
};

// Define props for the PasswordStrengthTable, passing passwordStrength
type PasswordStrengthTableProps = {
    passwordStrength: PasswordAnalyzeEntry[];
};

interface ReusedPasswordGroup {
    password: string;
    sites: string[];
}

type TableRow = {
    site: string;
    password: string;
    rowSpan?: number;
};

const PasswordsAnalysisReport: React.FC<PasswordStrengthTableProps> = ({ passwordStrength }) => {
    const chartCanvasRef = useRef<HTMLCanvasElement>(null);
    const chartInstanceRef = useRef<Chart | null>(null); // Remove the generic type for Chart

    const generateHealthScoreChart = () => {
        const ctx = chartCanvasRef.current;

        if (ctx) {
            if (chartInstanceRef.current) {
                chartInstanceRef.current.destroy();
            }

            const chartData = [
                passwordStrength.filter((p) => p.score <= 2).length,
                passwordStrength.filter((p) => p.score === 3).length,
                passwordStrength.filter((p) => p.score === 4).length,
                passwordStrength.filter((p) => p.score === 5).length,
            ];

            chartInstanceRef.current = new Chart(ctx, {
                type: "pie",
                data: {
                    labels: ["Weak", "Moderate", "Strong", "Very Strong"],
                    datasets: [
                        {
                            label: "Password Strength Distribution",
                            data: chartData,
                            backgroundColor: ["#FF6B6B", "#FFA94D", "#89E970FF", "#078B1DFF"],
                        },
                    ],
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: "top",
                        },
                        datalabels: {
                            color: "#ffffff",
                            formatter: (value) => `${value}`,
                            font: {
                                size: 14,
                                weight: "bold",
                            },
                        },
                    },
                },
                plugins: [ChartDataLabels],
            });
        }
    };

    const generatePDF = async () => {
        // Create a new jsPDF instance with standard A4 page size (210mm x 297mm)
        const doc = new jsPDF({
            format: 'a4'   
        });
    
        // Add executive summary
        doc.setFontSize(24);
    
        // Add the centered text to the PDF
        doc.setFont("Helvetica", "bold");
        doc.text("Executive Summary", 14, 20);
    
        doc.setFontSize(16); 
        doc.setFont("helvetica", "normal");
    
        doc.text(`Here is your report:`, 14, 40);
        doc.setFontSize(14); 
    
        const totalPasswords = passwordStrength.length;
        const weakPasswords = passwordStrength.filter((p) => p.score <= 2).length;
        const reusedPasswords = passwordStrength.filter((p, i, arr) =>
            arr.some((o, idx) => idx !== i && o.password === p.password)
        ).length;
    
        // Set the label color to black
        doc.setTextColor(0, 0, 0); 
        doc.text(`Total Passwords:`, 14, 50);
        // Set the value color
        doc.setTextColor(0, 0, 255); 
        doc.text(`${totalPasswords}`, 60, 50);
    
        doc.setTextColor(0, 0, 0); 
        doc.text(`Weak Passwords:`, 14, 60);
        doc.setTextColor(255, 0, 0);
        doc.text(`${weakPasswords}`, 65, 60);
    
        doc.setTextColor(0, 0, 0); 
        doc.text(`Reused Passwords:`, 14, 70);
        doc.setTextColor(255, 165, 0);
        doc.text(`${reusedPasswords}`, 65, 70);
    
        // Add the pie chart below the executive summary
        if (chartCanvasRef.current) {
            const chartImage = chartCanvasRef.current.toDataURL("image/png");
            const chartWidth = 400;
            const chartHeight = 100;
            const pageWidth = doc.internal.pageSize.width;
            // Calculate the X position to center the chart
            const chartX = (pageWidth - chartWidth) / 2;
            doc.addImage(chartImage, "PNG", chartX, 100, chartWidth, chartHeight); // place chart centered below executive summary
        }
    
        // Add weak passwords list on a new page
        doc.addPage();
        doc.setFontSize(24);
        doc.setFont("helvetica", "bold");
    
        // Get page width using the getWidth() method
        const pageWidth = doc.internal.pageSize.width;
        const fontSize = 24;
        const textWidth = doc.getStringUnitWidth("Weak Passwords") * fontSize / doc.internal.scaleFactor;
        const centerX = (pageWidth - textWidth) / 2;  // Calculate the X position to center the text
        doc.setTextColor(0, 0, 0); 
        doc.text("Weak Passwords", centerX, 20);
    
        doc.setFont("Helvetica", "normal");
        doc.setFontSize(14);
        const maxWidth = 180; // Set the maximum width for wrapping
        const text = "Here is a list of the weak passwords, kindly update them to increase your password security:";
        const lines = doc.splitTextToSize(text, maxWidth);
    
        // Now, render the lines with the desired Y-coordinate
        doc.text(lines, 14, 40);
    
        // Get the Y-coordinate after the text
        const textY = 40; 
        const tableStartY = textY + 10; // Add some margin between the text and the table
    
        const weakPasswordsList = passwordStrength
            .filter((p) => p.score <= 2)
            .map((entry) => [entry.url, entry.password]);
    
        // Generate the weak passwords table below the text
        doc.autoTable({
            head: [["URL", "Password"]],
            body: weakPasswordsList,
            startY: tableStartY,  // Specify the starting Y for the table
        });
    
        // Add reused passwords list
        doc.addPage();
        doc.setFontSize(24);
        doc.setFont("helvetica", "bold");
        doc.setTextColor(0, 0, 0); 
        doc.text("Reused Passwords", centerX, 20);
        
        // Group passwords by their reuse across multiple sites
        const reusedPasswordsMap = passwordStrength.reduce((acc, entry) => {
            if (acc.has(entry.password)) {
                acc.get(entry.password)?.sites.push(entry.url);
            } else {
                acc.set(entry.password, { password: entry.password, sites: [entry.url] });
            }
            return acc;
        }, new Map<string, ReusedPasswordGroup>());
        
        // Filter groups with more than one site
        const filteredReusedPasswordsList = Array.from(reusedPasswordsMap.values()).filter(group => group.sites.length > 1);
        
        // Create a table-friendly format with rowspan information
        const tableBody: TableRow[] = filteredReusedPasswordsList.flatMap(group =>
            group.sites.map((site, index) => ({
                site,
                password: index === 0 ? group.password : '', // Only include the password in the first row
                rowSpan: index === 0 ? group.sites.length : undefined, // Apply rowspan to the first row
            }))
        );
        
        let isGroup1 = true;  // Flag to alternate between two groups' shades

        doc.autoTable({
            head: [["Sites Reusing This Password", "Reused Password"]],
            body: tableBody.map((row, index) => {
                // If the row's password differs from the previous row's password, toggle the group flag
                if (index > 0 && row.password !== tableBody[index - 1].password) {
                    isGroup1 = !isGroup1;
                }

                return [
                    { content: row.site }, // Site column
                    {
                        content: row.password, // Password column
                        rowSpan: row.rowSpan, // Apply rowspan
                        styles: { valign: 'middle', halign: 'center' }, // Center vertically and horizontally
                    },
                ];
            }),
            startY: 40,
            theme: 'grid',
            styles: {
                fontSize: 10,
                fontStyle: 'normal',
                cellPadding: 4,
                lineColor: [255, 255, 255],
                lineWidth: 0.5,
            },
            bodyStyles: {
                minCellHeight: 10,
                fillColor: isGroup1 ? [255, 255, 255] : [220, 220, 220], // Alternate colors for groups
                textColor: [0, 0, 0],
            },
            margin: { top: 20, bottom: 20, left: 20, right: 20 },
            didDrawCell: (data) => {
                const row = data.row.raw as TableRow; // Explicitly cast to TableRow
                const nextRow = tableBody[data.row.index + 1] as TableRow | undefined; // Handle out-of-bound cases
                
                // Check if it's the last row of a group
                const isLastRowOfGroup =
                    data.section === 'body' &&
                    row.password !== '' && // Current row has a password
                    (!nextRow || nextRow.password === ''); // Next row belongs to a different group or doesn't exist

                if (isLastRowOfGroup) {
                    const lineY = data.cell.y + data.cell.height; // Calculate the Y position for the line
                    doc.setLineWidth(0.5);
                    doc.line(data.settings.margin.left, lineY, data.settings.margin.right, lineY); // Draw the line
                }
            },
        });
                                              
        doc.save("password-analysis-report.pdf");
    };       

    useEffect(() => {
        generateHealthScoreChart();

        return () => {
            if (chartInstanceRef.current) {
                chartInstanceRef.current.destroy();
            }
        };
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [passwordStrength]);

    return (
        <div className="password-strength">
            <div>
                <h2>Executive Summary</h2>
                <p>Total Passwords: {passwordStrength.length}</p>
                <p>Weak Passwords: {passwordStrength.filter((p) => p.score <= 2).length}</p>
                <p>Reused Passwords: {passwordStrength.filter((p, i, arr) =>
                    arr.some((o, idx) => idx !== i && o.password === p.password)
                ).length}</p>
            </div>

            <div style={{ textAlign: "center", marginTop: "30px" }}>
                <canvas ref={chartCanvasRef} id="strengthChart" />
            </div>

            <button onClick={generatePDF} style={{ marginTop: "20px" }}>
                Download Full Report as PDF
            </button>
        </div>
    );
};

export default PasswordsAnalysisReport;
