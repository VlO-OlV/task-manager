export default () => ({
    port: parseInt(process.env.PORT, 10) || 3000,
    secret: process.env.SECRET,
    jwt: {
        ttl: '86400s',
    },
    frontBaseUrl: process.env.FRONT_BASE_URL,
    redis: {
        host: process.env.REDIS_HOST,
        port: parseInt(process.env.REDIS_PORT, 10) || 6379,
        password: process.env.REDIS_PASSWORD,
    },
});