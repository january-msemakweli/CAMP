# MoAfyaCamps

A centralized platform for efficient health camp data collection and management.

## Features

- User registration and approval system
- Project and form management
- Real-time data collection
- Role-based access control (Admin/User)
- Supabase integration for data storage
- Responsive and modern UI

## Prerequisites

- Python 3.8 or higher
- Supabase account and project
- pip (Python package manager)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/MoAfyaCamps.git
cd MoAfyaCamps
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Create a `.env` file in the project root with the following variables:
```
FLASK_APP=app.py
FLASK_ENV=development
SECRET_KEY=your-secret-key-here
SUPABASE_URL=your-supabase-url-here
SUPABASE_KEY=your-supabase-key-here
```

5. Initialize the database:
```bash
flask db init
flask db migrate
flask db upgrade
```

## Running the Application

1. Start the Flask development server:
```bash
flask run
```

2. Access the application at `http://localhost:5000`

## Default Admin Credentials

- Username: admin
- Password: moafya123

## Usage

### Admin Features
- Approve/delete user registrations
- Create and manage projects
- Create and manage forms
- View and export data

### User Features
- Register and wait for approval
- View available projects
- Submit data through forms
- View submitted data

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details. 