# ImpactHub Backend

A robust Node.js + Express API for managing charitable campaigns and donations with integrated payment processing.

## Overview

ImpactHub Backend provides a comprehensive platform for managing charitable campaigns, processing secure donations, and tracking donor engagement. Built with modern web technologies and security best practices.

## Key Features

**Campaign Management**
- Browse and search campaigns with advanced filtering and pagination
- Category-based organization with dynamic statistics
- Featured campaigns and trending capabilities
- Impact reporting and progress tracking

**Donation Processing**
- Secure payment processing via Stripe
- Real-time payment confirmation and tracking
- Comprehensive donation history
- Support for anonymous donations

**User Management**
- JWT-based authentication with bcrypt password hashing
- Google OAuth integration
- User profiles with donation statistics
- Role-based access control (donor, organization, admin)

**Security & Performance**
- Rate limiting on critical endpoints
- Input validation and sanitization
- CORS protection
- Environment-based configuration  

## Technology Stack

| Category | Technology |
|----------|-----------|
| Runtime | Node.js |
| Framework | Express.js |
| Database | MongoDB + Mongoose ODM |
| Authentication | JWT, bcrypt, Google OAuth |
| Payment Processing | Stripe |
| Validation | express-validator |
| Security | CORS, Rate Limiting |

## Project Structure
charity-be/
├── controllers/         # Business logic layer
├── models/             # Database schemas
├── routes/             # API endpoint definitions
├── middleware/         # Authentication & validation
├── utils/              # Helper functions
├── uploads/            # File storage
├── server.js           # Application entry point
└── package.json        # Dependencies
├── seedDatabase.js      # Development data seeder
└── .env.example         # Environment template
```

## Quick Start

### 1. Install Dependencies
```bash
cd backend
npm install
```

### 2. Environment Setup
```bash
cp .env.example .env
```

Edit `.env` with your configuration:
```Getting Started

### Prerequisites

- Node.js (v14 or higher)
- MongoDB (v4.4 or higher)
- Stripe account for payment processing

### Installation

1. Clone the repository and install dependencies:
```bash
npm install
```

2. Configure environment variables:
```bash
cp .env.example .env
```

Edit `.env` with your configuration:
```env
NODE_ENV=development
PORT=5000
MONGODB_URI=mongodb://localhost:27017/impacthub
JWT_SECRET=your_secure_random_string
STRIPE_SECRET_KEY=sk_test_your_stripe_key
STRIPE_WEBHOOK_SECRET=whsec_your_webhook_secret
CLIENT_URL=http://localhost:3000
```

3. Ensure MongoDB is running and seed the database (optional):
```bash
npm run seed
```

4. Start the development server:
```bash
npm run dev
```

The API will be available at `http://localhost:5000/api`

### Available Commands
Documentation

### Health Check
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | API status check |

### Campaigns
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/campaigns` | List all campaigns (with filtering/pagination) |
| GET | `/api/campaigns/search` | Search campaigns by keyword |
| GET | `/api/campaigns/categories` | Get categories with campaign counts |
| GET | `/api/campaigns/featured` | Get featured campaigns |
| GET | `/api/campaigns/:id` | Get campaign details |
| GET | `/api/campaigns/:id/donations` | Get campaign donation history |
| GET | `/api/campaigns/:id/impact-reports` | Get campaign impact reports |
| POST | `/api/campaigns/:id/share` | Increment campaign share count |

### Donations
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/donations/create-payment-intent` | Initialize Stripe payment |
| POST | `/api/donations/confirm` | Confirm payment success |
| GET | `/api/donations/history/:email` | Get user donation history |
| POST | `/api/donations/webhook` | Stripe webhook handler |

### Users
| Metho Models

### Campaign
Core campaign information including title, description, financial targets, organization details, category, status, donation metrics, and social engagement tracking.

### Donation
Payment records with campaign references, donor information, transaction amounts, Stripe payment integration, and optional anonymity settings.

### User
User accounts with authentication credentials, OAuth integration, role-based permissions, donation history, and preference management.

## Security

The application implements multiple layers of security:

- **Authentication**: JWT tokens with configurable expiration
- **Password Security**: bcrypt hashing with salt rounds
- **Rate Limiting**: Endpoint-specific rate limits to prevent abuse
- **Input Validation**: Comprehensive validation and sanitization
- **CORS**: Configurable cross-origin resource sharing
- **Environment Variables**: Sensitive data stored securely

## Payment Integration

Stripe payment processing with the following capabilities:

- Secure payment intent creation and confirmation
- Real-time webhook handling for payment status updates
- Automatic campaign progress tracking
- Transaction history and reporting
- Support for multiple currencies

## Development

### Sample Data

The seed script provides realistic test data including:
- Multiple campaigns across various categories
- Sample user accounts with different roles
- Donation records with varied amounts
- Impact reports for demonstration purposes

Run `npm run seed` to populate your development database.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a pull request
