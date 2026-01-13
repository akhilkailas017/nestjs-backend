export interface AppConfig {
  mongoUri: string;

  admin: {
    email: string;
    passwordHash: string;
  };

  jwt: {
    accessSecret: string;
    accessExpiresIn: string;
    refreshSecret: string;
    refreshExpiresIn: string;
  };
}

export default (): AppConfig => {
  const {
    MONGO_URI,
    ADMIN_EMAIL,
    ADMIN_PASSWORD_HASH,
    JWT_ACCESS_SECRET,
    JWT_ACCESS_EXPIRES,
    JWT_REFRESH_SECRET,
    JWT_REFRESH_EXPIRES,
  } = process.env;

  if (!MONGO_URI) {
    throw new Error('MONGO_URI environment variable is required');
  }

  if (!ADMIN_EMAIL || !ADMIN_PASSWORD_HASH) {
    throw new Error('Admin credentials are required');
  }

  if (
    !JWT_ACCESS_SECRET ||
    !JWT_ACCESS_EXPIRES ||
    !JWT_REFRESH_SECRET ||
    !JWT_REFRESH_EXPIRES
  ) {
    throw new Error('JWT configuration is incomplete');
  }

  return {
    mongoUri: MONGO_URI,

    admin: {
      email: ADMIN_EMAIL,
      passwordHash: ADMIN_PASSWORD_HASH,
    },

    jwt: {
      accessSecret: JWT_ACCESS_SECRET,
      accessExpiresIn: JWT_ACCESS_EXPIRES,
      refreshSecret: JWT_REFRESH_SECRET,
      refreshExpiresIn: JWT_REFRESH_EXPIRES,
    },
  };
};
