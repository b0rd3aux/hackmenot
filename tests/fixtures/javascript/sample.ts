// Sample TypeScript file for testing

interface User {
    id: number;
    name: string;
    email: string;
}

type ApiResponse<T> = {
    data: T;
    status: number;
};

async function getUser(id: number): Promise<User> {
    const response = await fetch(`/api/users/${id}`);
    return response.json();
}

class ApiClient {
    private baseUrl: string;

    constructor(baseUrl: string) {
        this.baseUrl = baseUrl;
    }

    async get<T>(path: string): Promise<ApiResponse<T>> {
        const response = await fetch(`${this.baseUrl}${path}`);
        const data = await response.json();
        return { data, status: response.status };
    }
}

export { getUser, ApiClient, User, ApiResponse };
